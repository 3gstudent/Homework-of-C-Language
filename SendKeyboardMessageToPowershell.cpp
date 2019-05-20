#include <afx.h>

void SendKeyboardCommand(HWND hWnd, int command)
{
	printf("[+]Sending:0x%02x\r\n", command);
	PostMessage(hWnd, WM_KEYDOWN, command, 0);
	PostMessage(hWnd, WM_KEYUP, command, 0xC0000000);
}

HWND GetWindowHandleByPID(DWORD dwProcessID)
{
	HWND hWnd = GetTopWindow(0);
	while (hWnd)
	{
		DWORD pid = 0;
		DWORD dwTheardId = GetWindowThreadProcessId(hWnd, &pid);
		if (dwTheardId != 0)
		{
			if (pid == dwProcessID)
			{
				printf("[+]hWnd:%x\r\n", hWnd);
				return hWnd;
			}
		}
		hWnd = ::GetNextWindow(hWnd, GW_HWNDNEXT);
	}
	return NULL;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("\nSend keyboard messages to specified powershell process.\n");
		printf("Default command:whoami\n");
		printf("Usage:\n");
		printf("     %s <pid>\n", argv[0]);
		return 0;
	}
	DWORD pid;
	sscanf_s(argv[1], "%d", &pid);

	HWND hWnd = GetWindowHandleByPID(pid);
	if (hWnd == NULL)
	{
		printf("[!]I can't find it.\r\n");
		return 0;
	}
	
	char command[MAX_PATH] = "WHOAMI";	
	for (int i = 0; i < strlen(command); i++)
	{
		SendKeyboardCommand(hWnd, command[i]);
		Sleep(1);
	}
		
	//Enter
	SendKeyboardCommand(hWnd, VK_RETURN);

	return 0;
}
