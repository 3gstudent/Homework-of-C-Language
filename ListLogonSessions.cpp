#include <Windows.h>
#include <NTSecAPI.h>
#include <atltime.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#pragma comment(lib,"Secur32.lib")

DWORD GetStrWithPSID(PSID pSid, TCHAR* szBuffer, int nLength)
{
	SID_IDENTIFIER_AUTHORITY *psia = ::GetSidIdentifierAuthority(pSid);
	DWORD dwTopAuthority = psia->Value[5];
	_stprintf_s(szBuffer, nLength, _T("S-1-%lu"), dwTopAuthority);

	TCHAR szTemp[32];
	int iSubAuthorityCount = *(GetSidSubAuthorityCount(pSid));
	for (int i = 0; i < iSubAuthorityCount; i++)
	{
		DWORD dwSubAuthority = *(GetSidSubAuthority(pSid, i));
		_stprintf_s(szTemp, 32, _T("%lu"), dwSubAuthority);
		_tcscat_s(szBuffer, nLength, _T("-"));
		_tcscat_s(szBuffer, nLength, szTemp);
	}

	return 0;
}

VOID GetSessionData(PLUID session)
{
	PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
	NTSTATUS retval;
	WCHAR *usBuffer;
	int usLength;

	if (!session) 
	{
		wprintf(L"Error - Invalid logon session identifier.\n");
		return;
	}

	retval = LsaGetLogonSessionData(session, &sessionData);
	if (retval != STATUS_SUCCESS) 
	{
		wprintf(L"LsaGetLogonSessionData failed %lu \n",
		LsaNtStatusToWinError(retval));
		if (sessionData) 
		{
			LsaFreeReturnBuffer(sessionData);
		}
		return;
	}

	if (!sessionData) 
	{
		wprintf(L"Invalid logon session data. \n");
		return;
	}

	wprintf(L"    User name:    %ls\\%ls\n", sessionData->LogonDomain.Buffer, sessionData->UserName.Buffer);
	wprintf(L"    Auth package: %ls\n", sessionData->AuthenticationPackage.Buffer);

	switch ((SECURITY_LOGON_TYPE)sessionData->LogonType)
	{
		case Interactive:
			wprintf(L"    Logon type:   Interactive\n");
			break;
		case Network:
			wprintf(L"    Logon type:   Network\n");
			break;
		case Batch:
			wprintf(L"    Logon type:   Batch\n");
			break;
		case Service:
			wprintf(L"    Logon type:   Service\n");
			break;
		case Proxy:
			wprintf(L"    Logon type:   Proxy\n");
			break;
		case Unlock:
			wprintf(L"    Logon type:   Unlock\n");
			break;
		default:
			wprintf(L"    Logon type:   (none)\n");
			break;
	}

	wprintf(L"    Session:      %d\n", sessionData->Session);

	TCHAR szSID[MAX_PATH] = L"(none)";
	
	if (IsValidSid(sessionData->Sid))
		GetStrWithPSID(sessionData->Sid, szSID, MAX_PATH);

	wprintf(L"    Sid:          %s\n", szSID);

	FILETIME m_FileTime;
	m_FileTime.dwHighDateTime = sessionData->LogonTime.HighPart;
	m_FileTime.dwLowDateTime = sessionData->LogonTime.LowPart;
	CTime m_Time(m_FileTime);
	wprintf(L"    Logon time:   %02d/%02d/%04d %02d:%02d:%02d\n", m_Time.GetMonth(), m_Time.GetDay(), m_Time.GetYear(), m_Time.GetHour(), m_Time.GetMinute(), m_Time.GetSecond());

	wprintf(L"    Logon Server: %ls\n", sessionData->LogonServer.Buffer);
	wprintf(L"    DNS Domain:   %ls\n", sessionData->DnsDomainName.Buffer);
	wprintf(L"    UPN:          %ls\n", sessionData->Upn.Buffer);

	LsaFreeReturnBuffer(sessionData);
	return;
}

int _tmain(int argc, _TCHAR* argv[])
{
	PLUID sessions;
	ULONG count;
	NTSTATUS retval;
	int i;

	retval = LsaEnumerateLogonSessions(&count, &sessions);

	if (retval != STATUS_SUCCESS) {
		wprintf(L"LsaEnumerate failed %lu\n",
			LsaNtStatusToWinError(retval));
		return 1;
	}
	wprintf(L"ListLogonSessions - Lists logon session information\n");
	wprintf(L"[+] Total Sessions:%lu\n\n", count);

	for (i = 0; i < (int)count; i++)
	{
		wprintf(L"[%d] Logon session %08x:%08x\n", i, sessions[i].HighPart, sessions[i].LowPart);
		GetSessionData(&sessions[i]);
	}

	LsaFreeReturnBuffer(sessions);

	return 0;
}
