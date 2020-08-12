//Reference:https://github.com/etormadiv/HostingCLR
//Add a function of changing cElement to the number of Main arguments.(https://github.com/etormadiv/HostingCLR/blob/master/HostingCLR/HostingCLR.cpp#L218)
//Support passing multiple parameters to CLR.
#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>

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


int _tmain(int argc, _TCHAR* argv[])
{
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
