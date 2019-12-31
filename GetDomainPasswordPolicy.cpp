
#include <stdio.h>
#include <windows.h> 
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

int wmain(int argc, wchar_t *argv[])
{
	DWORD dwLevel = 0;
	USER_MODALS_INFO_0 *pBuf0 = NULL;
	USER_MODALS_INFO_3 *pBuf3 = NULL;
	NET_API_STATUS nStatus;
	LPTSTR pszServerName = NULL;

	if (argc != 2)
	{
		printf("Usage:\n");
		printf("\t%ws [\\\\ServerName]\n", argv[0]);
		exit(1);
	}

	// The server is not the default local computer.
	//
	if (argc == 2)
		pszServerName = (LPTSTR)argv[1];
	//
	// Call the NetUserModalsGet function; specify level 0.
	//
	nStatus = NetUserModalsGet((LPCWSTR)pszServerName,
		dwLevel,
		(LPBYTE *)&pBuf0);
	//
	// If the call succeeds, print the global information.
	//
	if (nStatus == NERR_Success)
	{
		if (pBuf0 != NULL)
		{
			printf("[+] Global password information:\n");
			printf("\tMinimum password length:  %d\n", pBuf0->usrmod0_min_passwd_len);
			printf("\tMaximum password age (d): %d\n", pBuf0->usrmod0_max_passwd_age / 86400);
			printf("\tMinimum password age (d): %d\n", pBuf0->usrmod0_min_passwd_age / 86400);
			printf("\tForced log off time (s):  %d\n", pBuf0->usrmod0_force_logoff);
			printf("\tPassword history length:  %d\n", pBuf0->usrmod0_password_hist_len);
		}
	}
	// Otherwise, print the system error.
	//
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	//
	// Free the allocated memory.
	//
	if (pBuf0 != NULL)
		NetApiBufferFree(pBuf0);

	dwLevel = 3;

	nStatus = NetUserModalsGet((LPCWSTR)pszServerName,
		dwLevel,
		(LPBYTE *)&pBuf3);
	//
	// If the call succeeds, print the global information.
	//
	if (nStatus == NERR_Success)
	{
		if (pBuf3 != NULL)
		{
			printf("[+] Lockout information:\n");
			printf("\tLockout duration (m):  %d\n", pBuf3->usrmod3_lockout_duration / 60);
			printf("\tLockout observation window (m): %d\n", pBuf3->usrmod3_lockout_observation_window / 60);
			printf("\tLockout threshold: %d\n", pBuf3->usrmod3_lockout_threshold);
		}
	}
	// Otherwise, print the system error.
	//
	else
		fprintf(stderr, "A system error has occurred: %d\n", nStatus);
	//
	// Free the allocated memory.
	//
	if (pBuf3 != NULL)
		NetApiBufferFree(pBuf3);

	return 0;
}

