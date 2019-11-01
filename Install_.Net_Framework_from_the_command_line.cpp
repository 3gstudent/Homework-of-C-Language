#include "stdafx.h"

#include <afx.h>
#include <Windows.h>

BOOL CALLBACK EnumChildWindowProc(HWND Child_hWnd, LPARAM lParam)
{		
	WCHAR szTitle[1024];
	if (Child_hWnd)
	{
		GetWindowText(Child_hWnd, szTitle, sizeof(szTitle));
		if (wcscmp(szTitle, L"&Install") == 0)
		{
			printf("[+] Catch it!\n");
			printf("[*] Handle: %08X\n", Child_hWnd);
			printf("[*] Caption: %ws\n", szTitle);
			printf("[*] 5.Enable the Install button.\n");	
			EnableWindow(Child_hWnd, TRUE);
			printf("[*] 6.Send the click command to &Install.\n");
			::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0,0));
			::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
			printf("[*] 7.You should wait for the installation to complete.\n");
		}
		return true;
	}
	return false;
}

BOOL CALLBACK EnumChildWindowProc2(HWND Child_hWnd, LPARAM lParam)
{
	WCHAR szTitle[1024];
	if (Child_hWnd)
	{
		GetWindowText(Child_hWnd, szTitle, sizeof(szTitle));
		if (wcscmp(szTitle, L"&Finish") == 0)
		{
			printf("[+] Catch it!\n");
			printf("[*] Handle: %08X\n", Child_hWnd);
			printf("[*] Caption: %ws\n", szTitle);
			printf("[*] 8.Send the click command to &Finish.\n");
			::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0, 0));
			::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
		}
		else if (wcscmp(szTitle, L"Restart &Later") == 0)
		{
			printf("[+] Catch it!\n");
			printf("[*] Handle: %08X\n", Child_hWnd);
			printf("[*] Caption: %ws\n", szTitle);
			printf("[*] 9.Send the click command to Restart &Later.\n");
			::PostMessage(Child_hWnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(0, 0));
			::PostMessage(Child_hWnd, WM_LBUTTONUP, MK_LBUTTON, MAKELPARAM(0, 0));
			printf("[*] 10.All done.\n");
			printf("[*] You need to wait for the system to reboot to complete the installation.\n");

			exit(0);
		}
		return true;
	}
	return false;
}

int _tmain(int argc, _TCHAR *argv[])
{
	if (argc != 3)
	{
		printf("\nAutomatically install Microsoft .NET Framework 4/4.5/4.5.1 in the background.\n");
		printf("Author: 3gstudent\n");	
		printf("You can get Microsoft .NET Framework 4 (Standalone Installer) from:\n");
		printf("	https://www.microsoft.com/en-US/Download/confirmation.aspx?id=17718\n");		
		printf("You can get Microsoft .NET Framework 4.5 (Web Installer) from:\n");
		printf("	https://www.microsoft.com/en-us/download/details.aspx?id=30653\n");
		printf("You can get Microsoft .NET Framework 4.5.1 (Offline Installer) from:\n");
		printf("	https://www.microsoft.com/en-us/download/details.aspx?id=40779\n");

		printf("Usage:\n");
		printf("     %ws <setup file path> <.NET Framework version>\n", argv[0]);
		printf("Eg.\n");
		printf("     %ws dotNetFx40_Full_x86_x64.exe 4\n", argv[0]);
		printf("     %ws dotNetFx45_Full_setup.exe 4.5\n", argv[0]);
		printf("     %ws NDP451-KB2858728-x86-x64-AllOS-ENU.exe 4.5.1\n", argv[0]);
		return 0;
	}
	WCHAR szWindow[48] = {0};

	if (wcscmp(argv[2], L"4") == 0)
	{
		wcscpy_s(szWindow, L"Microsoft .NET Framework 4 Setup");
	}
	else if (wcscmp(argv[2], L"4.5") == 0)
	{
		wcscpy_s(szWindow, L"Microsoft .NET Framework 4.5");
	}
	else if (wcscmp(argv[2], L"4.5.1") == 0)
	{
		wcscpy_s(szWindow, L"Microsoft .NET Framework 4.5.1");
	}
	else
	{
		printf("[!] Wrong parameter]\n");
		return 0;
	}
	printf("[+] Version: %ws\n", szWindow);

	printf("[*] 1.Check the installation environment.\n");
	HWND hWnd1 = FindWindow(NULL, szWindow);
	if (hWnd1 != NULL)
	{
		printf("[!]Another install is already running.\n");
		return 0;
	}

	printf("[*] 2.Run the setup file.\n");	
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	si.cb = sizeof(STARTUPINFO);
	si.lpReserved = NULL;
	si.lpDesktop = NULL;
	si.lpTitle = NULL;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.cbReserved2 = NULL;
	si.lpReserved2 = NULL;
	if (CreateProcess(NULL, argv[1], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == 0)
	{
		printf("[!] Wrong path.\n");
		return 0;
	}

	printf("[*] 3.Try to hide the main window.\n");
	while(1)
	{
		HWND hWnd2 = FindWindow(NULL, szWindow);
		ShowWindow(hWnd2, SW_HIDE);
		if (hWnd2 != NULL)
		{
			printf("[+] Catch it!\n");
			break;
		}

		Sleep(100);
	}

	printf("[*] Wait 10 seconds.\n");
	Sleep(10000);
	
	HWND hWnd3 = FindWindow(NULL, szWindow);
	if (hWnd3 == NULL)
	{
		printf("[!] I can't find the main window.\n");
		return 0;
	}
	
	printf("[*] 4.Try to eunm the child window.\n");
	EnumChildWindows(hWnd3, EnumChildWindowProc, 0);
	printf("[*] Waiting for the installation process...\n");
	while (1)
	{
		HWND hWnd4 = FindWindow(NULL, szWindow);
		EnumChildWindows(hWnd4, EnumChildWindowProc2, 0);	
		Sleep(100);
	}

	return 0;
}


