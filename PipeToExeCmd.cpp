
#include "stdafx.h"

#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "User32.lib")

char *ExeCmd(WCHAR *pszCmd)
{
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead, hWrite;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		return ("[!] CreatePipe failed.");
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfo(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	WCHAR command[MAX_PATH];
	wsprintf(command, L"cmd.exe /c %ws", pszCmd);

	if (!CreateProcess(NULL, command, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
		return ("[!] CreateProcess failed.");

	CloseHandle(hWrite);

	char buffer[4096] = { 0 };

	DWORD bytesRead;
	char strText[32768] = { 0 };

	while (true)
	{
		if (ReadFile(hRead, buffer, 4096 - 1, &bytesRead, NULL) == NULL)
			break;
		sprintf_s(strText, "%s\r\n%s", strText, buffer);
		memset(buffer, 0, sizeof(buffer));

	}
	//	printf("%s\n", strText);
	return strText;
}
int main()
{
	WCHAR *Command = L"ipconfig /all";
	char *data = ExeCmd(Command);
	printf("%s\n", data);
	return 0;
}
