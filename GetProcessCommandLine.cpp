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
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
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

	return 1;
}


BOOL getProcessCMD(DWORD pid) {
	int err = 0;
	// determine if 64 or 32-bit processor
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
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
	PROCESS_BASIC_INFORMATION pbi;
	ZeroMemory(&pbi, sizeof(pbi));


	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		printf("[!]OpenProcess error\r\n");
		return 0;
	}
	HANDLE hNewProcess = NULL;
	if (!DuplicateHandle(GetCurrentProcess(), hProc, GetCurrentProcess(), &hNewProcess, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		printf("[!]DuplicateHandle error\r\n");
		return 0;
	}

	// get process information
	_NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	err = query(hNewProcess, 0, &pbi, sizeof(pbi), NULL);
	if (err != 0)
	{
		CloseHandle(hNewProcess);
		free(peb);
		free(pp);
		printf("[!]NtQueryInformationProcess failed\r\n");
		return 0;
	}

	// read PEB
	if (!ReadProcessMemory(hNewProcess, pbi.PebBaseAddress, peb, pebSize, NULL))
	{
		CloseHandle(hNewProcess);
		free(peb);
		free(pp);
		printf("[!]ReadProcessMemory PEB failed\r\n");
		return 0;
	}

	// read ProcessParameters
	PBYTE* parameters = (PBYTE*)*(LPVOID*)(peb + ProcessParametersOffset); // address in remote process adress space
	if (!ReadProcessMemory(hNewProcess, parameters, pp, ppSize, NULL))
	{
		CloseHandle(hNewProcess);
		free(peb);
		free(pp);
		printf("[!]ReadProcessMemory Parameters failed\r\n");
		return 0;
	}

	printf("[*]ReadProcessMemory -> commandline -> ");
	// read CommandLine
	UNICODE_STRING* pCommandLine = (UNICODE_STRING*)(pp + CommandLineOffset);
	cmdLine = (PWSTR)malloc(pCommandLine->MaximumLength);
	if (!ReadProcessMemory(hNewProcess, pCommandLine->Buffer, cmdLine, pCommandLine->MaximumLength, NULL))
	{
		printf("Failed\r\n");
		CloseHandle(hNewProcess);
		free(peb);
		free(pp);
		free(cmdLine);
		printf("[!]ReadProcessMemory Parameters failed\r\n");
		return 0;
	}
	printf("Success\r\n");

	printf("[+]Commandline:%ws\n", cmdLine);

	return 1;

}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("\nGet the commandline of the selected process.\n");
		printf("Usage:\n");
		printf("     %s <pid>\n", argv[0]);
		return 0;
	}
	DWORD pid;
	sscanf_s(argv[1], "%d", &pid);
	getProcessCMD(pid);
	return 1;
}
