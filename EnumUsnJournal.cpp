#include <Windows.h>

int main()
{
	WCHAR driveletter[] = L"\\\\.\\C:";
	HANDLE hVol = CreateFile(driveletter, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	USN_JOURNAL_DATA journalData;
	PUSN_RECORD usnRecord;
	DWORD dwBytes;
	DWORD dwRetBytes;
	char buffer[USN_PAGE_SIZE];
	BOOL bDioControl = DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &dwBytes, NULL);
	if (!bDioControl) 
	{ 
		printf("[!]DeviceIoControl error\n");
		return 1; 
	}
	MFT_ENUM_DATA med;
	med.StartFileReferenceNumber = 0;
	med.LowUsn = 0;
	med.HighUsn = journalData.NextUsn;
	while(dwBytes > sizeof(USN))
	{ 
		memset(buffer, 0, sizeof(USN_PAGE_SIZE));
		bDioControl = DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &med, sizeof(med), &buffer, USN_PAGE_SIZE, &dwBytes, NULL);
		if (!bDioControl)
			break;
		dwRetBytes = dwBytes - sizeof(USN);
		usnRecord = (PUSN_RECORD)(((PUCHAR)buffer) + sizeof(USN));
		while (dwRetBytes > 0)
		{		
			printf("%.*ws\n", (int)(usnRecord->FileNameLength / 2), usnRecord->FileName);
			dwRetBytes -= usnRecord->RecordLength;
			usnRecord = (PUSN_RECORD)(((PCHAR)usnRecord) + usnRecord->RecordLength);
		}
		med.StartFileReferenceNumber = *(DWORDLONG*)buffer;
	}
	CloseHandle(hVol);
	return 0;
}
