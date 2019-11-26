#include <stdio.h>
#include <Windows.h>
#include <Processthreadsapi.h>
#pragma comment(lib, "Advapi32.lib")

static void add_mitigations(HANDLE hProc)
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature = { 0 };
	GetProcessMitigationPolicy(hProc, ProcessSignaturePolicy, &signature, sizeof(signature));
	printf("ProcessSignaturePolicy:\n");
	printf("   MicrosoftSignedOnly                        %u\n", signature.MicrosoftSignedOnly);
	signature.MicrosoftSignedOnly = 1;
	SetProcessMitigationPolicy(ProcessSignaturePolicy, &signature, sizeof(signature));

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
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
		return 0;
	}

	HANDLE hProcess = GetCurrentProcess();
	add_mitigations(hProcess);

//	getchar();

	return 0;
}

