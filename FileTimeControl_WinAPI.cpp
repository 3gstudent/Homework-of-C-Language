#include "windows.h"

int main(int argc, char *argv[])
{
	if (argc != 3 && argc != 4 && argc !=5)
	{
		printf("\nFileTimeControl_WinAPI\n");

		printf("Use GetFileTime and SetFileTime to view and modify the file's CreateTime,AccessTime and LastWriteTime\n");

		printf("Note:It doesn't support file's MFTChangeTime\n");

		printf("Author:3gstudent\n");
		
		printf("eg.\n");

		printf("	%s test.txt GetFileTime\n", argv[0]);

		printf("	%s test.txt CopyFileTimeFrom a.txt\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 CreateTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 AccessTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 LastWriteTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 AllTime\n", argv[0]);

		return -1;
	}
	HANDLE hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[!]CreateFile error:%d\n", GetLastError());

		return -1;
	
	}
	if (strcmp(argv[2], "GetFileTime") == 0)
	{
		printf("[*]GetFileTime Mode\n");		
		FILETIME ftCreateTime, ftAccessTime, ftLastWriteTime;
		SYSTEMTIME stCreateTimeUTC, stCreateTimeLocal, stAccessTimeUTC, stAccessTimeLocal, stLastWriteTimeUTC, stLastWriteTimeLocal;
		if (!GetFileTime(hFile, &ftCreateTime, &ftAccessTime, &ftLastWriteTime))
		{
			printf("[!]GetFileTime error:%d\n", GetLastError());

			CloseHandle(hFile);

			return -1;
		}	
		FileTimeToSystemTime(&ftCreateTime, &stCreateTimeUTC);
		FileTimeToSystemTime(&ftAccessTime, &stAccessTimeUTC);
		FileTimeToSystemTime(&ftLastWriteTime, &stLastWriteTimeUTC);
		SystemTimeToTzSpecificLocalTime(NULL, &stCreateTimeUTC, &stCreateTimeLocal);
		SystemTimeToTzSpecificLocalTime(NULL, &stAccessTimeUTC, &stAccessTimeLocal);
		SystemTimeToTzSpecificLocalTime(NULL, &stLastWriteTimeUTC, &stLastWriteTimeLocal);
			
		printf("[+]CreateTime:     %4d-%02d-%02d %02d:%02d:%02d\n", stCreateTimeLocal.wYear, stCreateTimeLocal.wMonth, stCreateTimeLocal.wDay, stCreateTimeLocal.wHour, stCreateTimeLocal.wMinute, stCreateTimeLocal.wSecond);
		printf("[+]AccessTime:     %4d-%02d-%02d %02d:%02d:%02d\n", stAccessTimeLocal.wYear, stAccessTimeLocal.wMonth, stAccessTimeLocal.wDay, stAccessTimeLocal.wHour, stAccessTimeLocal.wMinute, stAccessTimeLocal.wSecond);
		printf("[+]LastWriteTime:  %4d-%02d-%02d %02d:%02d:%02d\n", stLastWriteTimeLocal.wYear, stLastWriteTimeLocal.wMonth, stLastWriteTimeLocal.wDay, stLastWriteTimeLocal.wHour, stLastWriteTimeLocal.wMinute, stLastWriteTimeLocal.wSecond);		
		printf("[+]Done\n");
		CloseHandle(hFile);
		return 0;
	}
	else if(strcmp(argv[2], "CopyFileTimeFrom") == 0)
	{
		printf("[*]CopyFileTimeFrom Mode\n");
		if (argc != 4)
		{
			printf("[!]Wrong parameter\n");
			return 0;
		}

		HANDLE hFile2 = CreateFile(argv[3], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (hFile2 == INVALID_HANDLE_VALUE)
		{
			printf("[!]CreateFile error:%d\n", GetLastError());

			CloseHandle(hFile);

			return -1;

		}
		FILETIME ftCreateTime, ftAccessTime, ftLastWriteTime;
		if (!GetFileTime(hFile2, &ftCreateTime, &ftAccessTime, &ftLastWriteTime))
		{
			printf("[!]GetFileTime error:%d\n", GetLastError());

			CloseHandle(hFile2);

			CloseHandle(hFile);

			return -1;
		}	
		if (!SetFileTime(hFile, &ftCreateTime, &ftAccessTime, &ftLastWriteTime))
		{
			printf("[!]SetFileTime error:%d\n", GetLastError());

			CloseHandle(hFile);

			return -1;
		}
		printf("[+]Done\n");
		CloseHandle(hFile);
		return 0;
	}
	else
	{				
		printf("[*]SetTime Mode\n");
		if (argc != 5)
		{
			printf("[!]Wrong parameter\n");
			return 0;
		}
		SYSTEMTIME stNewTime;
		sscanf(argv[2], "%d-%d-%d", &stNewTime.wYear, &stNewTime.wMonth, &stNewTime.wDay);
		sscanf(argv[3], "%d:%d:%d", &stNewTime.wHour, &stNewTime.wMinute, &stNewTime.wSecond);

		FILETIME ftNewTime, ftNewLocalTime;
		SystemTimeToFileTime(&stNewTime, &ftNewTime);
		LocalFileTimeToFileTime(&ftNewTime, &ftNewLocalTime);
		if (strcmp(argv[4], "CreateTime") == 0)
		{
			if (!SetFileTime(hFile, &ftNewLocalTime, (LPFILETIME)NULL, (LPFILETIME)NULL))
				printf("[!]SetFileTime error:%s\n", GetLastError());
		}
		else if (strcmp(argv[4], "AccessTime") == 0)
		{
			if (!SetFileTime(hFile, (LPFILETIME)NULL, &ftNewLocalTime, (LPFILETIME)NULL))
				printf("[!]SetFileTime error:%s\n", GetLastError());
		}
		else if (strcmp(argv[4], "LastWriteTime") == 0)
		{
			if (!SetFileTime(hFile, (LPFILETIME)NULL, (LPFILETIME)NULL, &ftNewLocalTime))
				printf("[!]SetFileTime error:%s\n", GetLastError());
		}
		else if (strcmp(argv[4], "AllTime") == 0)
		{
			if (!SetFileTime(hFile, &ftNewLocalTime, &ftNewLocalTime, &ftNewLocalTime))
				printf("[!]SetFileTime error:%s\n", GetLastError());
		}
		else
		{
			printf("[!]Wrong parameter\n");
		}
		printf("[+]Done\n");
		CloseHandle(hFile);
		return 0;
	}
}
