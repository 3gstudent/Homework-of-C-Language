#include <windows.h>
#pragma pack(1)

typedef struct _BCF_HEADER {
	ULONG64 Flag1;
	ULONG64 Flag2;
	ULONG Unknown;
} BCFHEADER, *PBCFHEADER;

typedef struct _BCF_RECORD {
	ULONG Size;
} BCFRECORD, *PBCFRECORD;
#pragma pack()

int NewSize = 0;

char *DeleteRecord(PVOID mapAddress, char *TempBuf, int StopSize,WCHAR *FileName)
{
	char flag[16] = { 0xFE,0xFF,0xEE,0xFF,0x11,0x22,0x00,0x00,0x03,0x00,0x00,0x00,0x01,0x00,0x00,0x00 };
	if (memcmp(mapAddress, flag, 16))
	{
		printf("[!]Maybe it's not RecentFileCache.bcf");
		exit(0);
	}
	memcpy(TempBuf, mapAddress, 0x14);
	PBCFRECORD currentRecordPtr = NULL;
	PBCFRECORD nextRecordPtr = (PBCFRECORD)((PBYTE)mapAddress + 0x14);
	int DeleteSize = 0;
	int FlagSize = 0x14;
	while (FlagSize + DeleteSize < StopSize)
	{
		currentRecordPtr = nextRecordPtr;

		WCHAR *RecordName = new WCHAR[nextRecordPtr->Size + 1];
		memcpy(RecordName, nextRecordPtr + 1, nextRecordPtr->Size * 2 + 2);
		printf("%ws\n", RecordName);
		if (wcscmp(RecordName, FileName) == 0)
		{
			printf("[+]Data found:%ws\n", RecordName);
			DeleteSize += nextRecordPtr->Size * 2 + 6;
		}
		else
		{
			memcpy(TempBuf + FlagSize, currentRecordPtr, nextRecordPtr->Size * 2 + 6);
			FlagSize += nextRecordPtr->Size * 2 + 6;
		}

		nextRecordPtr = (PBCFRECORD)((PBYTE)nextRecordPtr + nextRecordPtr->Size * 2 + 6);
	}
	NewSize = FlagSize;
	return TempBuf;
}

int main(int argc, char *argv[])
{
		if (argc != 3)
	{
	printf("\nLoad the RecentFileCache.bcf under Win7 and delete the selected data.\n");
	printf("The new file will be saved as NewRecentFileCache.bcf.\n");
	printf("Author:3gstudent\n");
	printf("Usage:\n");
	printf("     %s <file path of RecentFileCache.bcf> <file name to be deleted>\n", argv[0]);
	printf("eg:\n");
	printf("     %s C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf c:\\windows\\system32\\msiexec.exe\n\n", argv[0]);
	printf("[!]Wrong parameter\n");
	return 0;
	}
	
	FILE* fp;
	int err = fopen_s(&fp, argv[1], "a+");
	if (err != 0)
	{
		printf("openfile error!");
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	unsigned char *buf = new unsigned char[len];
	fseek(fp, 0, SEEK_SET);
	fread(buf, len, 1, fp);
	wchar_t FileName[100];
	swprintf(FileName, 100, L"%hs", argv[2]);
	char *buf2 = new char[len];
	buf2 = DeleteRecord(buf, buf2, len, FileName);
	fclose(fp);

	FILE* fp2;
	err = fopen_s(&fp2, "NewRecentFileCache.bcf", "wb+");
	if (err != 0)
	{
		printf("createfile error!");
		return 0;
	}
	fwrite(buf2, NewSize, 1, fp2);
	fclose(fp2);

	return 0;
}
