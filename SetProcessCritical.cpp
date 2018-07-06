#include <windows.h>
#pragma comment(lib,"Advapi32.lib") 

#define ProcessBreakOnTermination 29

typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength);

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

BOOL CallNtSetInformationProcess(HANDLE hProcess, ULONG Flag)
{
	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess");
	if (!NtSetInformationProcess)
	{
		printf("[!]Could not find NtSetInformationProcess entry point in NTDLL.DLL\n");
		return 0;
	}
	if(NtSetInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessBreakOnTermination, &Flag, sizeof(ULONG))<0)
		printf("[!]NtSetInformationProcess error\n");
	return 1;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("\nSet the selected process as critical or not.\n");
		printf("Usage:\n");
		printf("     %s <pid> <flag>\n", argv[0]);
		printf("If flag=0: \n     Set the selected process is not critical.\n");
		printf("If flag=1: \n     Set the selected process as critical.If exit the process,the system will cause BSOD.\n");
		return 0;
	}
	
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	DWORD pid;
	sscanf_s(argv[1], "%d", &pid);

	HANDLE hProcess;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (memcmp(argv[2], "1", 1) == 0)
	{
		printf("[+]Try to set the selected process as critical... ");
		if(CallNtSetInformationProcess(hProcess,TRUE)==1)
			printf("done.\n");
		else
			printf("false.\n");
	}
	else
	{
		printf("[+]Try to set the selected process is not critical... ");
		if (CallNtSetInformationProcess(hProcess, FALSE) == 1)
			printf("done.\n");
		else
			printf("false.\n");
	}
	return 0;
}
