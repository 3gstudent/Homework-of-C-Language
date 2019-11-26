#include <tchar.h>
#include <stdio.h>
#include <Windows.h>
#include <Processthreadsapi.h>

static void show_mitigations(HANDLE hProc)
{
	PROCESS_MITIGATION_DEP_POLICY dep = { 0 };
	PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code = { 0 };
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strict_handle_check = { 0 };
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY system_call_disable = { 0 };
	ULONG64 mitigation_options = { 0 };
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension_point_disable = { 0 };
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = { 0 };
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	PROCESS_MITIGATION_FONT_DISABLE_POLICY font = { 0 };
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load = { 0 };
	PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY side_channel_isolation = { 0 };

	GetProcessMitigationPolicy(hProc, ProcessDEPPolicy, &dep, sizeof(dep));
	printf("ProcessDEPPolicy:\n");
	printf("   Enable                                     %u\n", dep.Enable);
	printf("   DisableAtlThunkEmulation                   %u\n", dep.DisableAtlThunkEmulation);

	GetProcessMitigationPolicy(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr));
	printf("ProcessASLRPolicy:\n");
	printf("   EnableBottomUpRandomization                %u\n", aslr.EnableBottomUpRandomization);
	printf("   EnableForceRelocateImages                  %u\n", aslr.EnableForceRelocateImages);
	printf("   EnableHighEntropy                          %u\n", aslr.EnableHighEntropy);
	printf("   DisallowStrippedImages                     %u\n", aslr.DisallowStrippedImages);

	GetProcessMitigationPolicy(hProc, ProcessDynamicCodePolicy, &dynamic_code, sizeof(dynamic_code));
	printf("ProcessStrictHandleCheckPolicy:\n");
	printf("   ProhibitDynamicCode                        %u\n", dynamic_code.ProhibitDynamicCode);

	GetProcessMitigationPolicy(hProc, ProcessStrictHandleCheckPolicy, &strict_handle_check, sizeof(strict_handle_check));
	printf("ProcessStrictHandleCheckPolicy:\n");
	printf("   RaiseExceptionOnInvalidHandleReference     %u\n", strict_handle_check.RaiseExceptionOnInvalidHandleReference);
	printf("   HandleExceptionsPermanentlyEnabled         %u\n", strict_handle_check.HandleExceptionsPermanentlyEnabled);

	GetProcessMitigationPolicy(hProc, ProcessSystemCallDisablePolicy, &system_call_disable, sizeof(system_call_disable));
	printf("ProcessSystemCallDisablePolicy:\n");
	printf("   DisallowWin32kSystemCalls                  %u\n", system_call_disable.DisallowWin32kSystemCalls);

	GetProcessMitigationPolicy(hProc, ProcessMitigationOptionsMask, &mitigation_options, sizeof(mitigation_options));
	printf("ProcessMitigationOptionsMask:\n");
	printf("   MitigationOptions                          %llx\n", mitigation_options);

	GetProcessMitigationPolicy(hProc, ProcessExtensionPointDisablePolicy, &extension_point_disable, sizeof(extension_point_disable));
	printf("ProcessExtensionPointDisablePolicy:\n");
	printf("   DisableExtensionPoints                     %u\n", extension_point_disable.DisableExtensionPoints);

	GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
	printf("ProcessControlFlowGuardPolicy:\n");
	printf("   EnableControlFlowGuard                     %u\n", cfg.EnableControlFlowGuard);

	GetProcessMitigationPolicy(hProc, ProcessSignaturePolicy, &signature, sizeof(signature));
	printf("ProcessSignaturePolicy:\n");
	printf("   MicrosoftSignedOnly                        %u\n", signature.MicrosoftSignedOnly);

	GetProcessMitigationPolicy(hProc, ProcessFontDisablePolicy, &font, sizeof(font));
	printf("ProcessFontDisablePolicy:\n");
	printf("   DisableNonSystemFonts                      %u\n", font.DisableNonSystemFonts);

	GetProcessMitigationPolicy(hProc, ProcessImageLoadPolicy, &image_load, sizeof(image_load));
	printf("ProcessImageLoadPolicy:\n");
	printf("   NoRemoteImages                             %u\n", image_load.NoRemoteImages);
	printf("   NoLowMandatoryLabelImages                  %u\n", image_load.NoLowMandatoryLabelImages);

	GetProcessMitigationPolicy(hProc, ProcessSideChannelIsolationPolicy, &side_channel_isolation, sizeof(side_channel_isolation));
	printf("ProcessSideChannelIsolationPolicy:\n");
	printf("   SmtBranchTargetIsolation                   %u\n", side_channel_isolation.SmtBranchTargetIsolation);
	printf("   IsolateSecurityDomain                      %u\n", side_channel_isolation.IsolateSecurityDomain);
	printf("   DisablePageCombine                         %u\n", side_channel_isolation.DisablePageCombine);
	printf("   SpeculativeStoreBypassDisable              %u\n", side_channel_isolation.SpeculativeStoreBypassDisable);

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

int main(int argc, const char *argv[])
{
	if (argc != 2)
	{
		printf("\nGetProcessMitigationPolicy for Win10.\n\n");
		printf("Usage:\n");
		printf("%s <pid>\n", argv[0]);
		return 0;
	}
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	DWORD dwTargetPid = 0;
	dwTargetPid = atoi(argv[1]);
	printf("[*] TargetPid:%d\n", dwTargetPid);

	HANDLE hProcess = GetCurrentProcess();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, dwTargetPid);
	if (hProcess == NULL)
	{
		printf("[!] Unable to open process %u, code %u\n", dwTargetPid, GetLastError());
		return 0;
	}
	show_mitigations(hProcess);
	return 0;
}
