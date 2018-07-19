#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib,"Advapi32.lib") 

BOOL InjectDll(UINT32 ProcessId, char *DllPath)
{
	if (strstr(DllPath, "\\\\") != 0)
	{
		printf("[!]Wrong Dll path\n");
		return FALSE;
	}
	if (strstr(DllPath, "\\") == 0)
	{
		printf("[!]Need Dll full path\n");
		return FALSE;
	}

	size_t len = strlen(DllPath) + 1;

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
		HMODULE Kernel32Module = GetModuleHandle("Kernel32");
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

BOOL FreeDll(UINT32 ProcessId, char *DllFullPath)
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
		HMODULE Kernel32Module = GetModuleHandle("Kernel32");
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

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Use CreateRemoteThread to inject dll,usually used under XP.\n\n");
		printf("Usage:\n");
		printf("%s <PID> <Dll Path>\n", argv[0]);
		return 0;
	}

	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	if (!InjectDll((DWORD)atoi(argv[1]), argv[2]))
	{
		printf("[!]InjectDll error \n");
		return 1;
	}

	if (!FreeDll((DWORD)atoi(argv[1]), argv[2]))
	{
		printf("[!]FreeDll error \n");
		return 1;
	}
	printf("[+]InjectDll success\n");

	return 0;
}
