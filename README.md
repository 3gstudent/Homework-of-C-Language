# Homework-of-C-Language
C/C++ code examples of my blog.

### SetProcessCritical.cpp

Set the selected process as critical or not.

If the process is critical,when exit the process,the system will cause BSOD.

And it can also be used to turn a critical process into normal.

### CheckCriticalProess.cpp

Check the selected process is critical or not.

### FindCriticalProcess.cpp

Look through all the process and find the critical processes.

###  CreateRemoteThread.cpp

Use CreateRemoteThread to inject dll,usually used under WinXP.

### NtCreateThreadEx + LdrLoadDll.cpp

Use NtCreateThreadEx + LdrLoadDll to inject dll.

Note:

You need use release mode to build it.


### FreeDll.cpp

Use NtCreateThreadEx to free dll.

Use to inject Dll into a process at many times.

### EnumerateProcess&GetFile'sHandle&CloseHandle(XP).cpp

Enumerate all processes and get specified file's handle,then choose whether to close it or not.

Support absolute path and relative path.

Support WinXP and Win7.

### EnumerateProcess&GetFile'sHandle&CloseHandle(Win8).cpp

Enumerate all processes and get specified file's handle,then choose whether to close it or not.

Support absolute path and relative path.

Support Win8 and later.

### GetProcessAuthority.cpp

Look through all the process and detect whether the process runs as admin.

### MasqueradePEBtoCopyfile.cpp

Masquerade current process' PEB into exploer.exe and use IFileOperation to copy file.

You can use this to copy file into "C:\\windows\\System32" with normal user permissions.

### DisableFirewall.cpp

Use to disable Windows Firewall with normal user permissions.

Expand on IFileOperation of UAC bypass.






