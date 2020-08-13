# Homework-of-C-Language
C/C++ code examples of my blog.

---

### SetProcessCritical.cpp

Set the selected process as critical or not.

If the process is critical,when exit the process,the system will cause BSOD.

And it can also be used to turn a critical process into normal.

### CheckCriticalProess.cpp

Check the selected process is critical or not.

### FindCriticalProcess.cpp

Look through all the process and find the critical processes.

---

###  CreateRemoteThread.cpp

Use CreateRemoteThread to inject dll,usually used under WinXP.

### NtCreateThreadEx + LdrLoadDll.cpp

Use NtCreateThreadEx + LdrLoadDll to inject dll.

Note:

You need use release mode to build it.

### FreeDll.cpp

Use NtCreateThreadEx to free dll.

Use to inject Dll into a process at many times.

---

### EnumerateProcess&GetFile'sHandle&CloseHandle(XP).cpp

Enumerate all processes and get specified file's handle,then choose whether to close it or not.

Support absolute path and relative path.

Support WinXP and later.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

### EnumerateProcess&GetFile'sHandle&CloseHandle(Win7).cpp

Enumerate all processes and get specified file's handle,then choose whether to close it or not.

Support absolute path and relative path.

Support Win7 and later.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

---

### GetPIDandHandle(evt).cpp

Get Eventlog Service PID and search evt file's Handle.

Use NtQuerySystemInformation to query SystemExtendedHandleInformation.

Support WinXP and later.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

### GetPIDandHandle(evtx).cpp

Get Eventlog Service PID and search evtx file's Handle.

Use NtQuerySystemInformation to query SystemHandleInformation.

Support Win7 and later.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

---

### GetProcessAuthority.cpp

Look through all the process and detect whether the process runs as admin.

### GetProcessCommandLine.cpp

Gets the command line of the selected process.

---

### MasqueradePEBtoCopyfile.cpp

Masquerade current process' PEB into exploer.exe and use IFileOperation to copy file.

You can use this to copy file into "C:\\windows\\System32" with normal user permissions.

### DisableFirewall.cpp

Use to disable Windows Firewall with normal user permissions.

Expand on IFileOperation of UAC bypass.

---

### CreateFileMapping.cpp

Create 2 file mapping object.

Use to share data between multiple processes.

### OpenFileMapping.cpp

Open the 2 file mapping object.

Use to share data between multiple processes.

### DeleteRecordbyTerminateProcess(ReplaceFile).cpp

Kill the eventlog service's process and replace the eventlog file,then restart the Eventlog Service.

---

### EnablePrivilegeandGetTokenInformation.cpp

Enable the SeDebugPrivilege of current process and then get the full privileges of current process.

It can also enable other privileges.

### EnableSeImpersonatePrivilege.cpp

Enable the SeImpersonatePrivilege of current process and then create an impersonation token.

Call the CreateProcessWithToken function, passing the current process token to get a process.

Using with RottenPotato,we will have full privilege on the system.

### EnableSeAssignPrimaryTokenPrivilege.cpp

Enable the SeAssignPrimaryTokenPrivilege of current process and then call the CreateProcessAsUser function, passing the current process token to get a process.

Using with RottenPotato,we will have full privilege on the system.

### EnableSeTcbPrivilege.cpp

Enable the SeBackupPrivilege of current process and then we can call LsaLogonUser with SeTcbPrivilege and add arbitrary groups to the resulting token returned by this call. 

We will add the group SID “S-1-5-18” to the token, this is the SID for the Local System account and if we are using a token that possesses it, we will have full privilege on the system. 

It will create a reg key at HKEY_LOCAL_MACHINE\SOFTWARE\testtcb.

We will have full privilege on the system.

### EnableSeBackupPrivilege.cpp

Enable the SeBackupPrivilege of current process and then read the password hashes of local Administrator accounts from the registry.

The file will be saved as `C:\\test\\SAM`,`C:\\test\\SECURITY` and `C:\\test\\SYSTEM`.

We will have read access on the system.

### EnableSeRestorePrivilege.cpp

Enable the SeRestorePrivilege of current process and then create a reg key at HKEY_LOCAL_MACHINE\SOFTWARE\testrestore.

We will have write access on the system.

### EnableSeCreateTokenPrivilege.cpp

Enable the SeCreateTokenPrivilege of current process and then create primary tokens via the ZwCreateToken API.

After that enable the local administrator group on the token and enable SeDebugPrivilege and SeTcbPrivilege.

We will have all access on the system.

### EnableSeLoadDriverPrivilege.cpp

Enable the SeLoadDriverPrivilege of current process and then load the driver into the kernel.

First you need to add two reg keys,the command is:

`reg add hkcu\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\test\Capcom.sys"`

`reg add hkcu\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1`

Then run me to load the driver(C:\test\Capcom.sys) into the kernel.

We will have all access on the system.

### EnableSeTakeOwnershipPrivilege.cpp

Enable the SeTakeOwnershipPrivilege of current process and then have write access to a registry key "hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".
Then we can write it in "Medium" permission.

Eg.

`reg add "hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v takeownership /t REG_SZ /d "C:\\Windows\\System32\\calc.exe"`

We will have write access on the system' registry key.

### EnableSeDebugPrivilege.cpp

Enable the SeDebugPrivilege of current process and then we can inject a dll into the process. 

We will have full privilege on the system.

---

### portscan.cpp

Use to scan port.

The timeout is 3 seconds.

python version:

https://github.com/3gstudent/Homework-of-Python/blob/master/portscan.py

---

### ListRecentFileCache.cpp

Load the RecentFileCache.bcf in Win7 and print the data.

The RecentFileCache.bcf is replaced by Amcache.hve in Win8.

### DeleteRecentFileCache.cpp

Load the RecentFileCache.bcf under Win7 and delete the selected data.

The new file will be saved as NewRecentFileCache.bcf.

---

### ListLogonSessions.cpp

List logon session information.

The output format is the same as LogonSessions.

https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions

---

### FileTimeControl_WinAPI.cpp

Use GetFileTime and SetFileTime to view and modify the file's CreateTime,AccessTime and LastWriteTime.

Note:It doesn't support file's MFTChangeTime.

Support file and folder.

### FileTimeControl_NTAPI.cpp

Use NtQueryInformationFile and NtSetInformationFile to view and modify the file's CreateTime,AccessTime,LastWriteTime and MFTChangeTime.

reference:https://github.com/rapid7/meterpreter/blob/master/source/extensions/priv/server/timestomp.c

Only support file.

---

### EnumUsnJournal.cpp

Enumerate the Usn Journal Record in drive C.

---

### ProcessCommandlineSpoofing.cpp

Implementing SwampThing with C++

Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/SwampThing

Spoof process command line args (x32/64). Essentially you create a process in a suspended state, rewrite the PEB, resume and finally revert the PEB. The end result is that logging infrastructure will record the fake command line args instead of the real ones. 

---

### SendKeyboardMessageToPowershell.cpp

Send keyboard messages to specified powershell process.

Default command:whoami

You can get the Virtual-Key Codes from: https://docs.microsoft.com/en-us/windows/desktop/inputdev/virtual-key-codes

### SendKeyboardMessageToPowershell(Get-History).cpp

Send keyboard messages to specified powershell process.

Default command:Get-History|export-csv $env:temp"\history.csv"

### GetOSVersion.cpp

Use to detect the OS's Version.

It includes Windows Vista/Win 7/Windows Server 2008/Windows Server 2008 R2/Windows Server 2012/Windows 10.

### sekurlsa-wdigest.cpp

Use to get plain-text credentials of the 64-bit OS.

This is a simple implementation of Mimikatz's sekurlsa::wdigest

Support:

 - Win7 x64/Windows Server 2008 x64/Windows Server 2008R2 x64
 - Win8 x64/Windows Server 2012 x64/Windows Server 2012R2 x64
 - Win10_1507(and before 1903) x64

Source: https://gist.github.com/xpn/12a6907a2fce97296428221b3bd3b394

The following functions have been added:

 - EnableDebugPrivilege
 - GetOSVersion
 - Support different OS

---

### UrlDecode.cpp

Use to decode URL.

Support multi-byte character sets and Unicode character sets.

Support the following characters:
- %20->blank space 
- %22->"
- %27->'

### TextToHtmlofNewline.cpp

Use to convert line breaks (\n) in text to line breaks (</br>) in HTML.

---
### UsePipeToExeCmd.cpp

Use pipe to execute CMD commands.

---

### HTTPServerWebshell.cpp

Use the HTTP Server API to perform server-side tasks.

This is a POC that implements remote control through the browser.

Reference:

https://docs.microsoft.com/en-us/windows/win32/http/http-server-sample-application

---

### Install_.Net_Framework_from_the_command_line.cpp

Automatically install Microsoft .NET Framework 4/4.5/4.5.1 in the background.

You can get Microsoft .NET Framework 4 (Standalone Installer) from:https://www.microsoft.com/en-US/Download/confirmation.aspx?id=17718

You can get Microsoft .NET Framework 4.5 (Web Installer) from:https://www.microsoft.com/en-us/download/details.aspx?id=30653

You can get Microsoft .NET Framework 4.5.1 (Offline Installer) from:https://www.microsoft.com/en-us/download/details.aspx?id=40779

---

### GetProcessMitigationPolicyForWin8.cpp

Check the ProcessMitigationPolicy of the selected process.

Support: Win8-Win10

### GetProcessMitigationPolicyForWin10.cpp

Check the ProcessMitigationPolicy of the selected process.

Support: Win10

### SetProcessMitigationPolicy(Signature)ForWin8_CurrentProcess.cpp

Enable the ProcessSignaturePolicy(MicrosoftSignedOnly) of the current process.

Support: Win8-Win10

### SetProcessMitigationPolicy(Signature)ForWin10_CurrentProcess.cpp

Enable the ProcessSignaturePolicy(MicrosoftSignedOnly) of the current process.

Support: Win10

---

### QueryADObject.cpp

Reference:

https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Win7Samples/netds/adsi/activedir/QueryUsers/vc

https://github.com/outflanknl/Recon-AD

This program queries for objects in the current user's domain.

---

### GetDomainPasswordPolicy

Use to get the password policy of the current domain.

### CheckUserBadPwdPolicy

Use to get all the domain users' badPasswordTime and badPwdCount properties.

---

### tsssp_client.cpp

tsssp::client of kekeo

Source:https://github.com/gentilkiwi/kekeo

Usage:

```
tsssp_client.exe <target>
```

Eg:

```
tsssp_client.exe localhost
tsssp_client.exe Computer01.test.com
```

---

### File_XOR_generator.cpp

Use to XOR the contents of a file.

Usage:

```
File_XOR_generator.exe <file path> <XOR inputs>
```

Eg:

```
File_XOR_generator.exe test.exe 0x01
```

### HostingCLR_with_arguments_XOR.cpp

Reference:https://github.com/etormadiv/HostingCLR

Add a function of changing cElement to the number of Main arguments.(https://github.com/etormadiv/HostingCLR/blob/master/HostingCLR/HostingCLR.cpp#L218)

Support passing multiple parameters to CLR.

### HostingCLR_with_arguments_XOR_TamperETW.cpp

Reference:https://github.com/etormadiv/HostingCLR

Add a function of changing cElement to the number of Main arguments.(https://github.com/etormadiv/HostingCLR/blob/master/HostingCLR/HostingCLR.cpp#L218)

Support passing multiple parameters to CLR.

All patching EtwEventWrite codes are from https://github.com/outflanknl/TamperETW/

You need to add [Syscalls.asm](https://github.com/outflanknl/TamperETW/blob/master/TamperETW/UnmanagedCLR/Syscalls.asm) when building.

---






