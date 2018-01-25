// WIN32-Recon.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <iostream>

int main()
{
	if (IsDebuggerPresent()) {
		std::cout << "[*] Debugger is here run!";
		return 1;
	}
    return 0;
}

