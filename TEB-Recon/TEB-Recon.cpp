// TEB-Recon.cpp : Defines the entry point for the console application.


#include <iostream>
#include "stdafx.h"
#include <windows.h>
#include "Winternl.h"
#include <stdlib.h>
#include <stdio.h>


#define WIN32_LEAN_AND_MEAN

PPEB getPeb(void);

int main()
{
	// define our vars
	PPEB pPeb = NULL;
	BYTE dBug;

	pPeb = getPeb();
	std::cout << &pPeb << std::endl;
	dBug = pPeb->BeingDebugged;
	std::wcout << dBug << std::endl;
}

PPEB getPeb() {
	PVOID tmp = NULL;
	__asm
	{
		mov eax, fs:[0x30]
		mov tmp, eax
	}
	return (PPEB)tmp;
}


