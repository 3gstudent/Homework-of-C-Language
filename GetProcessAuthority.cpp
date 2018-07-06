#include <windows.h>  
#include <TlHelp32.h>  
BOOL IsRunasAdmin(HANDLE hProcess)  
{  
    BOOL bElevated = FALSE;    
    HANDLE hToken = NULL;    
    if (!OpenProcessToken(hProcess,TOKEN_QUERY,&hToken))  
        return FALSE;   
    TOKEN_ELEVATION tokenEle;  
    DWORD dwRetLen = 0;    
    if ( GetTokenInformation(hToken,TokenElevation,&tokenEle,sizeof(tokenEle),&dwRetLen))  
    {    
        if (dwRetLen == sizeof(tokenEle))  
        {  
            bElevated = tokenEle.TokenIsElevated;    
        }  
    }    
    CloseHandle(hToken);    
    return bElevated;    
}  

int main()  
{  
	PROCESSENTRY32 pinfo; 
	HANDLE hProcess,hModule;
	BOOL bRunAsAdmin;
	hModule = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  
	BOOL report = Process32First(hModule, &pinfo);  
	printf("\n%-20s	 PID	Run as Admin\n","Process");
	printf("====================	====	============\n");
	while(report) 
	{ 
		printf("%-20s	%4d	",pinfo.szExeFile,pinfo.th32ProcessID); 
		hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pinfo.th32ProcessID);
		bRunAsAdmin = IsRunasAdmin(hProcess);  
		if (bRunAsAdmin)  
			printf("%-12s\n","Yes");  
		else
			printf("\n");
		report=Process32Next(hModule, &pinfo);    
	}
	CloseHandle(hModule);  

	return 0;  
} 
