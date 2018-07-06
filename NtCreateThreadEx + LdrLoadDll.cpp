//Need to use release mode to complile.

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#pragma comment(lib,"Advapi32.lib") 
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef DWORD64(WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, *PTHREAD_DATA;

HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd()
{
	return 0;
}

HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;

	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)
	{
		printf("[!]GetProcAddress (\"NtCreateThreadEx\")error\n");
		return NULL;
	}
	((_NtCreateThreadEx64)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
	if (hThread == NULL)
	{
		printf("[!]MyCreateRemoteThread : NtCreateThreadEx error\n");
		return NULL;
	}

	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		printf("[!]MyCreateRemoteThread : WaitForSingleObject error\n");
		return NULL;
	}
	return hThread;
}

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
	size_t converted = 0;
	wchar_t* DllFullPath;
	DllFullPath = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, DllFullPath, len, DllPath, _TRUNCATE);
	
	LPVOID pThreadData = NULL;
	LPVOID pCode = NULL;
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
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
		memcpy(data.DllName, DllFullPath, (wcslen(DllFullPath) + 1) * sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(ProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error\n");
			__leave;
		}

		BOOL bWriteOK = WriteProcessMemory(ProcessHandle, pThreadData, &data, sizeof(data), NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		pCode = VirtualAllocEx(ProcessHandle, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error,%d\n", GetLastError());
			__leave;
		}
		bWriteOK = WriteProcessMemory(ProcessHandle, pCode, (PVOID)ThreadProc, SizeOfCode, NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		hThread = MyCreateRemoteThread(ProcessHandle, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]MyCreateRemoteThread error\n");
			__leave;
		}

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(ProcessHandle, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(ProcessHandle, pCode, 0, MEM_RELEASE);
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

	HANDLE ProcessHandle = NULL;
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		printf("[!]OpenProcess error\n");
		return FALSE;
	}

	LPTHREAD_START_ROUTINE FreeLibraryAddress = NULL;
	HMODULE Kernel32Module = GetModuleHandle("Kernel32");
	FreeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "FreeLibrary");
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]NtCreateThreadEx error\n");
		return FALSE;
	}
	HANDLE ThreadHandle = NULL;
	NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)FreeLibraryAddress, me.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
	if (ThreadHandle == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]ThreadHandle error\n");
		return FALSE;
	}
	if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
	{
		printf("[!]WaitForSingleObject error\n");
		return FALSE;
	}
	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);
	return TRUE;
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
		printf("Use NtCreateThreadEx to inject dll\n\n");
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
