#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")
// #######################################################################
// ############ DEFINITIONS
// #######################################################################
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define FILE_NON_DIRECTORY_FILE 0x00000040

typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FilePositionInformation = 14,
	FileEndOfFileInformation = 20,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;							// Created             
	LARGE_INTEGER LastAccessTime;                       // Accessed    
	LARGE_INTEGER LastWriteTime;                        // Modifed
	LARGE_INTEGER ChangeTime;                           // Entry Modified
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI *pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(WINAPI *pNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);


// #######################################################################
// ############ FUNCTIONS
// #######################################################################

/* returns 0 on error, 1 on success. this function set the MACE values based on
the input from the FILE_BASIC_INFORMATION structure */
DWORD SetFileMACE(HANDLE file, FILE_BASIC_INFORMATION fbi) {


//	HANDLE ntdll = NULL;
	IO_STATUS_BLOCK iostatus;
	pNtSetInformationFile NtSetInformationFile = NULL;

//	ntdll = LoadLibrary("ntdll.dll");
//	if (ntdll == NULL) {
//		return 0;
//	}

	NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationFile");
	if (NtSetInformationFile == NULL) {
		return 0;
	}

	if (NtSetInformationFile(file, &iostatus, &fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		return 0;
	}

	/* clean up */
//	FreeLibrary(ntdll);

	return 1;
}

/* returns the handle on success or NULL on failure. this function opens a file and returns
the FILE_BASIC_INFORMATION on it. */
HANDLE RetrieveFileBasicInformation(char *filename, FILE_BASIC_INFORMATION *fbi) {

	HANDLE file = NULL;
//	HANDLE ntdll = NULL;
	pNtQueryInformationFile NtQueryInformationFile = NULL;
	IO_STATUS_BLOCK iostatus;

	file = CreateFile(filename, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return 0;
	}

	/* load ntdll and retrieve function pointer */
//	ntdll = LoadLibrary("ntdll.dll");
//	if (ntdll == NULL) {
//		CloseHandle(file);
//		return 0;
//	}

	/* retrieve current timestamps including file attributes which we want to preserve */
	NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL) {
		CloseHandle(file);
		return 0;
	}

	/* obtain the current file information including attributes */
	if (NtQueryInformationFile(file, &iostatus, fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		CloseHandle(file);
		return 0;
	}

	/* clean up */
//	FreeLibrary(ntdll);

	return file;
}

// returns 0 on error, 1 on success. this function converts a SYSTEMTIME structure to a LARGE_INTEGER
DWORD ConvertLocalTimeToLargeInteger(SYSTEMTIME localsystemtime, LARGE_INTEGER *largeinteger) {

	// the local time is stored in the system time structure argument which should be from the user
	// input. the user inputs the times in local time which is then converted to utc system time because
	// ntfs stores all timestamps in utc, which is then converted to a large integer

	// MSDN recommends converting SYSTEMTIME to FILETIME via SystemTimeToFileTime() and
	// then copying the values in FILETIME to a ULARGE_INTEGER structure.

	FILETIME filetime;
	FILETIME utcfiletime;
	DWORD result = 0;

	/*
	result = GetTimeZoneInformation(&timezone);
	if (result == TIME_ZONE_ID_INVALID) {
	printf("Error: Could not obtain the local time zone information.\n");
	return 0;
	}

	if (TzSpecificLocalTimeToSystemTime(&timezone, &localsystemtime, &utcsystemtime) == 0) {
	printf("Error: Couldn't convert local time to UTC time.\n");
	return 0;
	}
	*/

	// convert the SYSTEMTIME structure to a FILETIME structure
	if (SystemTimeToFileTime(&localsystemtime, &filetime) == 0) {
		return 0;
	}

	// convert the local file time to UTC
	if (LocalFileTimeToFileTime(&filetime, &utcfiletime) == 0) {
		return 0;
	}

	/* copying lowpart from a DWORD to DWORD, and copying highpart from a DWORD to a LONG.
	potential data loss of upper values 2^16, but acceptable bc we wouldn't be able to set
	this high even if we wanted to because NtSetInformationFile() takes a max of what's
	provided in LARGE_INTEGER */
	largeinteger->LowPart = utcfiletime.dwLowDateTime;
	largeinteger->HighPart = utcfiletime.dwHighDateTime;

	return 1;
}

/* returns 0 on error, 1 on success. this function converts a LARGE_INTEGER to a SYSTEMTIME structure */
DWORD ConvertLargeIntegerToLocalTime(SYSTEMTIME *localsystemtime, LARGE_INTEGER largeinteger) {

	FILETIME filetime;
	FILETIME localfiletime;
	DWORD result = 0;

	filetime.dwLowDateTime = largeinteger.LowPart;
	filetime.dwHighDateTime = largeinteger.HighPart;

	if (FileTimeToLocalFileTime(&filetime, &localfiletime) == 0) {
		return 0;
	}

	if (FileTimeToSystemTime(&localfiletime, localsystemtime) == 0) {
		return 0;
	}
	/*
	result = GetTimeZoneInformation(&timezone);
	if (result == TIME_ZONE_ID_INVALID) {
	printf("Error: Could not obtain the local time zone information.\n");
	return 0;
	}

	if (SystemTimeToTzSpecificLocalTime(&timezone, &utcsystemtime, localsystemtime) == 0) {
	printf("Error: Couldn't convert UTC time to local time.\n");
	return 0;
	}
	*/
	return 1;
}

/* returns 1 on success or 0 on failure. this function converts an input string into a SYSTEMTIME structure */
DWORD ParseDateTimeInput(char *inputstring, SYSTEMTIME *systemtime) {

	char day[10];
	char daynight[3];

	if (sscanf_s(inputstring, "%9s %hu/%hu/%hu %hu:%hu:%hu %2s", day, &systemtime->wMonth, &systemtime->wDay, &systemtime->wYear, &systemtime->wHour, &systemtime->wMinute, &systemtime->wSecond, daynight) == 0) {
		return 0;
	}

	/* sanitize input */
	if (strlen(day) > 0) {
		CharLower(day);
	}
	else {
		return 0;
	}

	do {
		if (day[0] == 'm') { if (strncmp(day, "monday", 6) == 0) { systemtime->wDayOfWeek = 1; break; } }
		if (day[0] == 't') {
			if (strncmp(day, "tuesday", 7) == 0) { systemtime->wDayOfWeek = 2; break; }
			if (strncmp(day, "thursday", 8) == 0) { systemtime->wDayOfWeek = 4; break; }
		}
		if (day[0] == 'w') { if (strncmp(day, "wednesday", 9) == 0) { systemtime->wDayOfWeek = 3; break; } }
		if (day[0] == 'f') { if (strncmp(day, "friday", 6) == 0) { systemtime->wDayOfWeek = 5; break; } }
		if (day[0] == 's') {
			if (strncmp(day, "saturday", 8) == 0) { systemtime->wDayOfWeek = 6; break; }
			if (strncmp(day, "sunday", 6) == 0) { systemtime->wDayOfWeek = 0; break; }
		}

		return 0;
	} while (0);


	if (systemtime->wMonth < 1 || systemtime->wMonth > 12) {
		return 0;
	}
	if (systemtime->wDay < 1 || systemtime->wDay > 31) {
		return 0;
	}
	if (systemtime->wYear < 1601 || systemtime->wYear > 30827) {
		return 0;
	}

	if (strlen(daynight) > 0) {
		CharLower(daynight);
	}
	else {
		return 0;
	}
	if (strncmp(daynight, "am", 2) == 0) {
		if (systemtime->wHour < 1 || systemtime->wHour > 12) {
			return 0;
		}
	}
	else if (strncmp(daynight, "pm", 2) == 0) {
		if (systemtime->wHour < 1 || systemtime->wHour > 12) {
			return 0;
		}
		if (systemtime->wHour != 12) { systemtime->wHour += 12; }
	}
	else {
		return 0;
	}

	if (systemtime->wMinute < 0 || systemtime->wMinute > 59) {
		return 0;
	}
	if (systemtime->wSecond < 0 || systemtime->wSecond > 59) {
		return 0;
	}

	/* it doesnt matter what the millisecond value is because the ntfs resolution for file timestamps is only up to 1s */
	systemtime->wMilliseconds = 0;

	return 1;
}

// takes a file a sets the time values to the minimum possible value, return 1 on success or 0 on failure
DWORD SetMinimumTimeValues(char *filename) {

	HANDLE file = NULL;
	FILE_BASIC_INFORMATION fbi;
	SYSTEMTIME userinputtime;

	// open the file and retrieve information
	file = RetrieveFileBasicInformation(filename, &fbi);
	if (file == NULL) {
		return 0;
	}

	userinputtime.wYear = 1601;
	userinputtime.wMonth = 1;
	userinputtime.wDayOfWeek = 0;
	userinputtime.wDay = 1;
	userinputtime.wHour = 0;
	userinputtime.wMinute = 0;
	userinputtime.wSecond = 0;
	userinputtime.wMilliseconds = 0;
	if ((ConvertLocalTimeToLargeInteger(userinputtime, &fbi.ChangeTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.CreationTime) == 0) ||
		(ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastAccessTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastWriteTime) == 0)) {
		return 0;
	}
	if (SetFileMACE(file, fbi) == 0) { return 0; }

	return 1;
}

// this function recursively blanks all files from the specified directory so that EnCase cannot see anything
DWORD TheCraigOption(char *directoryname) {

	// general variables
	HANDLE file = NULL;
	char currentfiletarget[MAX_PATH + 1];

	// file search variables
	HANDLE find = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData;
	char fulldirectorypath[MAX_PATH + 1];

	// set the target directories
	strncpy_s(fulldirectorypath, sizeof(fulldirectorypath), directoryname, strlen(directoryname) + 1);
	strncat_s(fulldirectorypath, sizeof(fulldirectorypath), "\\*", 3);

	// search the directory
	find = FindFirstFile(fulldirectorypath, &FindFileData);
	if (find == INVALID_HANDLE_VALUE) {
		if (GetLastError() == 5) { // access denied
			return 1;
		}
		return 0;
	}

	// recursively call TheCraigOption if the file type is a directory
	if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		if ((strncmp(FindFileData.cFileName, ".", 1) != 0) && (strncmp(FindFileData.cFileName, "..", 2) != 0)) {
			strncpy_s(currentfiletarget, sizeof(currentfiletarget), directoryname, strlen(directoryname) + 1);
			strncat_s(currentfiletarget, sizeof(currentfiletarget), "\\", 2);
			strncat_s(currentfiletarget, sizeof(currentfiletarget), FindFileData.cFileName, strlen(FindFileData.cFileName));
			if (TheCraigOption(currentfiletarget) == 0) {
				return 0;
			}
		}
	}
	else {
		// set the full file name and lower the time values
		strncpy_s(currentfiletarget, sizeof(currentfiletarget), directoryname, strlen(directoryname) + 1);
		strncat_s(currentfiletarget, sizeof(currentfiletarget), "\\", 2);
		strncat_s(currentfiletarget, sizeof(currentfiletarget), FindFileData.cFileName, strlen(FindFileData.cFileName));
		if (SetMinimumTimeValues(currentfiletarget) == 0) {
			//return 0;
		}
	}

	// recursively set all values
	while (FindNextFile(find, &FindFileData) != 0) {

		// recursively call TheCraigOption if the file type is a directory
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if ((strncmp(FindFileData.cFileName, ".", 1) != 0) && (strncmp(FindFileData.cFileName, "..", 2) != 0)) {
				strncpy_s(currentfiletarget, sizeof(currentfiletarget), directoryname, strlen(directoryname) + 1);
				strncat_s(currentfiletarget, sizeof(currentfiletarget), "\\", 2);
				strncat_s(currentfiletarget, sizeof(currentfiletarget), FindFileData.cFileName, strlen(FindFileData.cFileName));
				if (TheCraigOption(currentfiletarget) == 0) {
					return 0;
				}
			}
		}
		else {
			// set the full file name and lower the time values
			strncpy_s(currentfiletarget, sizeof(currentfiletarget), directoryname, strlen(directoryname) + 1);
			strncat_s(currentfiletarget, sizeof(currentfiletarget), "\\", 2);
			strncat_s(currentfiletarget, sizeof(currentfiletarget), FindFileData.cFileName, strlen(FindFileData.cFileName));
			if (SetMinimumTimeValues(currentfiletarget) == 0) {
				//return 0;
			}
		}
	}

	// cleanup find data structures
	if (FindClose(find) == 0) {
		return 0;
	}
	if (GetLastError() != ERROR_NO_MORE_FILES) {
		if (GetLastError() == 5) { // access denied
			return 1;
		}
		return 0;
	}

	return 1;
}

DWORD GetFileTime(char *filename)
{
	HANDLE file = NULL;
	FILE_BASIC_INFORMATION fbi;
	SYSTEMTIME stCreateTimeLocal, stAccessTimeLocal, stLastWriteTimeLocal, stMFTChangeTimeLocal;

	file = RetrieveFileBasicInformation(filename, &fbi);
	if (file == NULL) {
		printf("[!]RetrieveFileBasicInformation error\n");
		return 0;
	}

	if ((ConvertLargeIntegerToLocalTime(&stCreateTimeLocal, fbi.CreationTime) == 0) || (ConvertLargeIntegerToLocalTime(&stAccessTimeLocal, fbi.LastAccessTime) == 0) ||
		(ConvertLargeIntegerToLocalTime(&stLastWriteTimeLocal, fbi.LastWriteTime) == 0) || (ConvertLargeIntegerToLocalTime(&stMFTChangeTimeLocal, fbi.ChangeTime) == 0)) {
		printf("[!]ConvertLargeIntegerToLocalTime error\n");
		CloseHandle(file);
		return 0;
	}

	printf("[+]CreateTime:     %4d-%02d-%02d %02d:%02d:%02d\n", stCreateTimeLocal.wYear, stCreateTimeLocal.wMonth, stCreateTimeLocal.wDay, stCreateTimeLocal.wHour, stCreateTimeLocal.wMinute, stCreateTimeLocal.wSecond);
	printf("[+]AccessTime:     %4d-%02d-%02d %02d:%02d:%02d\n", stAccessTimeLocal.wYear, stAccessTimeLocal.wMonth, stAccessTimeLocal.wDay, stAccessTimeLocal.wHour, stAccessTimeLocal.wMinute, stAccessTimeLocal.wSecond);
	printf("[+]LastWriteTime:  %4d-%02d-%02d %02d:%02d:%02d\n", stLastWriteTimeLocal.wYear, stLastWriteTimeLocal.wMonth, stLastWriteTimeLocal.wDay, stLastWriteTimeLocal.wHour, stLastWriteTimeLocal.wMinute, stLastWriteTimeLocal.wSecond);
	printf("[+]MFTChangeTime:  %4d-%02d-%02d %02d:%02d:%02d\n", stMFTChangeTimeLocal.wYear, stMFTChangeTimeLocal.wMonth, stMFTChangeTimeLocal.wDay, stMFTChangeTimeLocal.wHour, stMFTChangeTimeLocal.wMinute, stMFTChangeTimeLocal.wSecond);
	CloseHandle(file);
	return 1;
}

// this function replaces fileA's file time by fileB's file time
DWORD CopyFileTimeFrom(char *fileA, char *fileB)
{
	HANDLE hA = NULL;
	HANDLE hB = NULL;
	FILE_BASIC_INFORMATION fbiB;
	hB = RetrieveFileBasicInformation(fileB, &fbiB);
	if (hB == NULL) {
		printf("[!]RetrieveFileBasicInformation error\n");
		return 0;
	}

	hA = CreateFileA(fileA, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hA == INVALID_HANDLE_VALUE) {
		printf("[!]CreateFile error:%s\n",fileA);
		CloseHandle(hB);
		return 0;
	}
	if (SetFileMACE(hA, fbiB) == 0) {
		printf("[!]SetFileMACE error\n");
		CloseHandle(hA);
		CloseHandle(hB);
		return 0;
	}
	CloseHandle(hA);
	CloseHandle(hB);
	return 1;

}

DWORD SetFileTime(char *filename, SYSTEMTIME userinputtime,int flag)
{
	HANDLE file = NULL;
	FILE_BASIC_INFORMATION fbi;

	// open the file and retrieve information
	file = RetrieveFileBasicInformation(filename, &fbi);
	if (file == NULL) {
		return 0;
	}
	switch (flag)
	{
	case 1:
	{
		if (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.CreationTime) == 0) {
			CloseHandle(file);
			return 0;
		}
		break;
	}

	case 2:
	{
		if (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastAccessTime) == 0) {
			CloseHandle(file);
			return 0;
		}
		break;
	}
	case 3:
	{
		if (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastWriteTime) == 0) {
			CloseHandle(file);
			return 0;
		}
		break;
	}
	case 4:
	{
		if (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.ChangeTime) == 0) {
			CloseHandle(file);
			return 0;
		}
		break;
	}
	case 5:
	{
		if ((ConvertLocalTimeToLargeInteger(userinputtime, &fbi.ChangeTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.CreationTime) == 0) ||
			(ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastAccessTime) == 0) || (ConvertLocalTimeToLargeInteger(userinputtime, &fbi.LastWriteTime) == 0)) {
			CloseHandle(file);
			return 0;
		}
		break;
	}
	}
	if (SetFileMACE(file, fbi) == 0) {
		printf("[!]SetFileMACE error\n");
		CloseHandle(file);
		return 0; 
	}
	CloseHandle(file);
	return 1;

}

int main(int argc, char *argv[])
{
	if (argc != 3 && argc != 4 && argc != 5)
	{
		printf("\nFileTimeControl_NTAPI\n");

		printf("Use NtQueryInformationFile and NtSetInformationFile to view and modify the file's CreateTime,AccessTime,LastWriteTime and MFTChangeTime\n");

		printf("Author:3gstudent\n");

		printf("Reference:https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/timestomp.c\n");

		printf("eg.\n");
		
		printf("	%s test.txt GetFileTime\n", argv[0]);

		printf("	%s test.txt SetMinimumTime\n", argv[0]);

		printf("	%s test.txt CopyFileTimeFrom a.txt\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 CreateTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 AccessTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 LastWriteTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 MFTChangeTime\n", argv[0]);

		printf("	%s test.txt 2000-01-01 01:01:01 AllTime\n", argv[0]);


		return 0;
	}
	if (strcmp(argv[2], "GetFileTime") == 0)
	{
		printf("[*]GetFileTime Mode\n");
		if(GetFileTime(argv[1]) == 1) {
			printf("[+]Done\n");
		}
		return 1;
	}
	else if (strcmp(argv[2], "SetMinimumTime") == 0)
	{
		printf("[*]SetMinimumTime Mode\n");
		if (SetMinimumTimeValues(argv[1]) == 1) {
			printf("[+]Done\n");
		}
		return 1;
	}

	else if (strcmp(argv[2], "CopyFileTimeFrom") == 0)
	{
		printf("[*]CopyFileTimeFrom Mode\n");
		if (argc != 4)
		{
			printf("[!]Wrong parameter\n");
			return 0;
		}

		if (CopyFileTimeFrom(argv[1], argv[3]) == 1) {
			printf("[+]Done\n");
		}
		return 1;
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
		if (strcmp(argv[4], "CreateTime") == 0)
		{
			SetFileTime(argv[1], stNewTime, 1);
		}
		else if (strcmp(argv[4], "AccessTime") == 0)
		{
			SetFileTime(argv[1], stNewTime, 2);
		}
		else if (strcmp(argv[4], "LastWriteTime") == 0)
		{
			SetFileTime(argv[1], stNewTime, 3);
		}
		else if (strcmp(argv[4], "MFTChangeTime") == 0)
		{
			SetFileTime(argv[1], stNewTime, 4);
		}
		else if (strcmp(argv[4], "AllTime") == 0)
		{
			SetFileTime(argv[1], stNewTime, 5);
		}
		else
		{
			printf("[!]Wrong parameter\n");
		}
		printf("[+]Done\n");
		return 1;
	}
}
