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

void ListRecord(PVOID mapAddress)
{
	char flag[16] = { 0xFE,0xFF,0xEE,0xFF,0x11,0x22,0x00,0x00,0x03,0x00,0x00,0x00,0x01,0x00,0x00,0x00 };
	if (memcmp(mapAddress, flag, 16))
	{
		printf("[!]Maybe it's not RecentFileCache.bcf");
		exit (0);
	}
	PBCFRECORD currentRecordPtr = NULL;
	PBCFRECORD nextRecordPtr = (PBCFRECORD)((PBYTE)mapAddress + 0x14);
	while (nextRecordPtr)
	{
		currentRecordPtr = nextRecordPtr;
		
		WCHAR *RecordName = new WCHAR[nextRecordPtr->Size + 1];
		memcpy(RecordName, nextRecordPtr + 1 , nextRecordPtr->Size * 2 + 2);
		printf("%ws\n", RecordName);
		nextRecordPtr = (PBCFRECORD)((PBYTE)nextRecordPtr + nextRecordPtr->Size * 2 + 6);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("\nLoad the RecentFileCache.bcf in Win7 and print the data.\n");
		printf("Author:3gstudent\n");
		printf("Usage:\n");
		printf("     %s <file path of RecentFileCache.bcf>\n", argv[0]);
		printf("eg:\n");
		printf("     %s C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf\n\n", argv[0]);
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
	ListRecord(buf);
	fclose(fp);

	return 0;
}
