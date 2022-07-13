#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <inttypes.h>
#include <windows.h>

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 4096

typedef struct CommandLineArgs
{
    BOOL bDecryptDump;
    BOOL bListen;
    BOOL bDecryptDumpFile;
    WCHAR DumpFileName[MAX_PATH];
    WCHAR PortToListen[6];
} CommandLineArgs, * pCommandLineArgs;

/*
* Parses the supplied command line arguments and assigns user choice flags to the pCmdArgs structure
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL ParseArgs(pCommandLineArgs pCmdArgs);

/*
* Manages the decryption of a dump file recived in memory via sockets.
* This function creates the sockets for handeling the connections from the remote target machine the dump is sent from.
* When the dump is recived, it will then be decrypted and wrrited to disk.
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
*/
BOOL ReciveDump(pCommandLineArgs pCmdArgs);

/*
* Manages the decryption of a dump file by its path, the dump file should exist on the file system
* This function will be used in cases of which an ecrypted file has been created but not sent remotly. The encrypted file can then be decrypted by this function.
* @param FilePath - A pointer to a wide character that represents the full path of the encrypted dump file on the file system
* @return BOOL - TRUE or FALSE
*/
BOOL DecryptDumpFile(WCHAR FilePath[MAX_PATH]);

/*
* Performs the actual decryption of a given encrypted buffer
* @param DumpBuffer - A pointer to the dump buffer in memory
* @param BytesRead - The number of the bytes read, indicates the amount of bytes to decrypt
*/
void Decryptor(PVOID DumpBuffer, int BytesRead);

/*
* Generates a random file name and assigns it to the pFileName variable
* @param pFileName - A pointer to a wide character that represents the file name
*/
void GenerateOutFileName(WCHAR* pFileName);

/*
* Validates that the wide character string supplied contains only digits
* @param String - A pointer to wide string
* @return BOOL - TRUE or FALSE
*/
BOOL ValidateNumber(WCHAR* String);

/*
* Prints the usage menu
*/
void Usage();

/*
* Retrieves and prints the correspondent error message of the last error code
* @param FunctionName - The function name that failed, used for better visibility
*/
void GetError(WCHAR* FunctionName);