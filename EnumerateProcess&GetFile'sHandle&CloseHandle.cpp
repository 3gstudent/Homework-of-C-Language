#include <windows.h>
#include <stdio.h>
#include <process.h>
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

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
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


int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("\nEnumerate all processes and get specified file's handle,then choose whether to close it or not\n");
		printf("Usage:\n");
		printf("     %s <absolute or relative file path> <flag>\n", argv[0]);
		printf("If flag=0: \n     Enumerate all processes and get specified file's handle.\n");
		printf("If flag=1: \n     Enumerate all processes and get specified file's handle,then close it.\n");
		printf("eg:\n");
		printf("     %s system.evtx 0\n", argv[0]);
		return 0;
	}

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle = NULL;
	ULONG i;
	DWORD ErrorPID = 0;
	SYSTEM_HANDLE handle = { 0 };
	wchar_t buf1[100];
	swprintf(buf1, 100, L"%hs", argv[1]);
	_wcslwr_s(buf1, wcslen(buf1) + 1);

	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

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

		if (handle.ObjectTypeNumber == 0x1e)//select File Type
		{
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
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				CloseHandle(processHandle);
				continue;
			}

			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
			{

				objectNameInfo = realloc(objectNameInfo, returnLength);
				if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
				{
					//				printf("[%#x] %.*S: (could not get name)\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
					free(objectTypeInfo);
					free(objectNameInfo);
					CloseHandle(dupHandle);
					CloseHandle(processHandle);
					continue;
				}
			}
			objectName = *(PUNICODE_STRING)objectNameInfo;
			if (objectName.Length)
			{
				_wcslwr_s(objectName.Buffer, wcslen(objectName.Buffer) + 1);
				if (wcsstr(objectName.Buffer, buf1) != 0)
				{
					printf("[+]HandleName:%.*S\n", objectName.Length / 2, objectName.Buffer);
					printf("[+]Pid:%d\n", handle.ProcessId);
					printf("[+]Handle:%#x\n", handle.Handle);
					printf("[+]Type:%#x\n", handle.ObjectTypeNumber);
					printf("[+]ObjectAddress:0x%p\n", handle.Object);
					printf("[+]GrantedAccess:%#x\n", handle.GrantedAccess);

					if (memcmp(argv[2], "1", 1) == 0)
					{
						printf("[+]Try to close the file's handle... ");

						if (DuplicateHandle(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_CLOSE_SOURCE))
						{
							CloseHandle(dupHandle);
							printf("done.\n");
						}
						else
							printf("false.\n");
					}
				}
			}
			else
			{
				//			printf("[%#x] %.*S: (unnamed)\n",handle.Handle,objectTypeInfo->Name.Length / 2,objectTypeInfo->Name.Buffer);
			}
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
		}
	}
	free(handleInfo);
	return 0;
}
