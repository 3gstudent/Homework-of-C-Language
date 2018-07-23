#include <windows.h>
#include <stdio.h>
#define BUF_SIZE 256

int main(int argc, char *argv[])
{
	HANDLE hMapFile1, hMapFile2;
	char *pBuf1;
	char *pBuf2;
	TCHAR szName1[] = L"Global\\SharedMappingObject1";
	TCHAR szName2[] = L"Global\\SharedMappingObject2";

	hMapFile1 = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,szName1);
	if (hMapFile1 == NULL)
	{
		printf("[!]Could not create file mapping object (%d).\n", GetLastError());
		return 1;
	}
	pBuf1 = (char *)MapViewOfFile(hMapFile1,FILE_MAP_ALL_ACCESS,0,0,BUF_SIZE);
	if (pBuf1 == NULL)
	{
		printf("[!]Could not map view of file (%d).\n", GetLastError());
		CloseHandle(hMapFile1);
		return 1;
	}
	//	MessageBox(NULL, pBuf, TEXT("Process2"), MB_OK);
	DWORD EventRecordID = 0;
	sscanf_s(pBuf1, "%d", &EventRecordID);
	printf("[+]EventRecordID:%d\n", EventRecordID);
	UnmapViewOfFile(pBuf1);
	CloseHandle(hMapFile1);


	hMapFile2 = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,szName2);
	if (hMapFile2 == NULL)
	{
		printf("[!]Could not create file mapping object (%d).\n", GetLastError());
		return 1;
	}
	pBuf2 = (char *)MapViewOfFile(hMapFile2,FILE_MAP_ALL_ACCESS,0,0,BUF_SIZE);
	if (pBuf2 == NULL)
	{
		printf("[!]Could not map view of file (%d).\n", GetLastError());
		CloseHandle(hMapFile2);
		return 1;
	}
	//	MessageBox(NULL, pBuf, TEXT("Process2"), MB_OK);
	DWORD offset = 0;
	sscanf_s(pBuf2, "%d", &offset);
	printf("[+]offset:%#x\n", offset);
	UnmapViewOfFile(pBuf2);
	CloseHandle(hMapFile2);

	return 0;
}
