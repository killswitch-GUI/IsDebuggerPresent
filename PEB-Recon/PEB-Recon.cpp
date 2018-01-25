// PEB-Recon.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "Winternl.h"
#include <iostream>

typedef NTSTATUS (*CALL)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);


int main()
{
	// define our vars
	HMODULE ntHandle;
	HANDLE currentProcess;
	// deref pointer?
	PROCESS_BASIC_INFORMATION pData;
	DWORD pLength = 0;
	CALL fCall;

	// ntdll.dll is part of the windows loader so 
	// we should have no issue simple finding a handle
	// in our current process context
	ntHandle = GetModuleHandle(L"ntdll.dll");

	// we need to find some functions now with our handle
	fCall = (CALL) GetProcAddress(
		ntHandle,
		"NtQueryInformationProcess"
	);

	// setup current proc handle
	currentProcess = GetCurrentProcess();

	// NtQueryInformationProcess our current handle
	if (NULL != fCall) {
		(fCall)(
			currentProcess,
			ProcessBasicInformation,
			&pData,
			sizeof(pData),
			&pLength
			);

		std::cout << "[*] Buffer size: " << pLength << std::endl;
		std::cout << "[*] ProcessBasicInformation Pointer: " << &pLength << std::endl;
		
		// now get the required pointer for PEB
		PPEB pPeb;
		pPeb = pData.PebBaseAddress;
		
		// now check for pointer and if so go forth
		if (NULL != pPeb)
		{	
			std::cout << "[*] PEB Pointer: " << pPeb << std::endl;
			BYTE dBug;
			dBug = pPeb->BeingDebugged;
			std::wcout << "[*] BeingDebugged BYTE: " << dBug << std::endl;
		}
	}
	else {
		// no handle bye
		std::cout << "[!] BAIL.." << std::endl;
	}

    return 0;

}

