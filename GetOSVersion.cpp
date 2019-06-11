
#include <Windows.h>
#include <string>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

void GetOSVersion()
{	
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);

	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		printf("Windows 10\n");
		return;
	}

	SYSTEM_INFO info;
	GetSystemInfo(&info);
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		switch (os.dwMajorVersion)
		{
		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("Windows Vista\n");
				else
					printf("Windows Server 2008\n");
				break;
			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("Windows 7\n");
				else
					printf("Windows Windows Server 2008 R2\n");
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("Windows 8\n");			
				else
					printf("Windows Server 2012\n");
				break;
			}
			break;
		default:
			printf("Too old\n");
		}

	}
	else
		printf("Error\n");
}

void main()
{
	GetOSVersion();
}
