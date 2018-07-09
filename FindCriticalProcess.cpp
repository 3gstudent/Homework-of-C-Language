#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib") 
#pragma comment(lib,"Advapi32.lib") 

#define ProcessBreakOnTermination 29
typedef int ProcessInformationClass;
typedef NTSTATUS(NTAPI * _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	ProcessInformationClass  informationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

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

BOOL CheckProcess(DWORD pid)
{
	printf("[%4d]  ",pid);
	HANDLE hProcess;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("System\n");
		return 0;
	}
	NTSTATUS status;
	ULONG breakOnTermination;
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		printf("[!]Could not find NtQueryInformationProcess entry point in NTDLL.DLL\n");
		return 0;
	}
	status = NtQueryInformationProcess(hProcess, ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG), NULL);
	if (status<0)
		printf("[!]NtQueryInformationProcess error\n");
	if (breakOnTermination == 1)
		printf("Critical[!]\n");
	else
	printf("Normal\n");
}

BOOL EnumProcess()
{
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		printf("[!]EnumProcesses error\n");
		return 0;
	}
	cProcesses = cbNeeded / sizeof(DWORD);
	for (i = 0; i < cProcesses; i++)
		if (aProcesses[i] != 0)
		{
			CheckProcess(aProcesses[i]);
		}
	return 1;
}

int main(int argc, char *argv[])
{
	printf("[*]Try to find the critical process\n\n");
	printf("[PID]   [Type]\n");
	printf("======  =======\n");
	EnumProcess();
}
