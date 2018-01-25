# IsDebuggerPresent

Recently I got an itch to revisit some necessary sandbox and anti-reversing techniques. While these often are overlooked for Red Teamers, they can play a valuable part in what you code branches too in the event of a debugger or VM. After all knowing we may have been exposed may be critical to the covert operation your trying to run?

I decided that comparing three excellent debugger check TTPs would be of interest and the research could probably benefit some. I know recently this area is of great importance for initial access. I would find interest in the ability to alert on IR actions and potentially beacon out with maybe a magic packet etc. Nothing necessarily new, but nice to have on you initial access implant, loader, or even persistence.

TL;DR: https://github.com/killswitch-GUI/IsDebuggerPresent

## IsDebuggerPresent() Method Using WinAPI
Yes, a known and very common TTP for malware authors to use. Often this method is built into packers and loaders. But, this is easily discovered by dumping the import table. Unless you are doing some import table obfuscation this is likely to be caught or at least labeled as malicious at first glance from RE or Automated solutions.

The first project during this test was easy: https://github.com/killswitch-GUI/IsDebuggerPresent/tree/master/WIN32-Recon 

```
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
```

This, of course, is a contrived example and is very simple, it should be noted that all samples are compiled for Win32 (x86). All of the code was compiled with Visual Studio 2017 C++.

After some initial analysis of the binary, it was flagged with 10/65 on Virus Total [WIN32-Recon.exe](https://www.virustotal.com/#/file/9284a09d7019210b6ba56715061578f816e7cef9e3a58cbe67b638277b2f5491/detection). For one simple API call, this isn't an idea as you can imagine. So let's take this a step further.

## NtQueryInformationProcess() Method Using PEB
Using undocumented Windows API comes with a price in many cases, this requires specific API calls to load the proper function calls required. This can be subverted, not in this case. I think starting with the code will be ideal and working through ti step by step: https://github.com/killswitch-GUI/IsDebuggerPresent/tree/master/PEB-Recon

```
// PEB-Recon.cpp : Defines the entry point for the console application.

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
```

1. We use GetModuleHandle() to locate our function call of choice. IT should be noted that many people always use LoadLibary('ntdll.dll'). This isn't entirely necessary in many cases. This is almost always loaded as the Windows loader requires it and should be present in loaded modules. 
2. We need GetProcAddress() specifically since we don't have access to compile against ntdll.dll even though "Winternl.h" is available. We need to find our NtQueryInformationProcess() function.
3. We call GetCurrentProcess() to obtain a handle to our current process.
4. We then call fCall() which is merely NtQueryInformationProcess. This will give us access to the PROCESS_BASIC_INFORMATION structure. This is heavily documented and rarely changes for minor releases. Particularly we now find the base address of the PEB data structure. 
5. We now populate our PPEB structure "pPeb." The PEB structure contains a wealth of information, and in this case, it contains a FLAG of 0x0 or 0x1 to denote active debugging.
6. Finally, we use pPeb->BeingDebugged to check if we are being debugged.

So how did we fare with this technique? We managed a 2/65 rating against Virus Total: [PEB-Recon.exe](https://www.virustotal.com/#/file/4d33feec67851004aca39f6d4b4ff183adbd640e80c4efac4fdc0dea728fe452/detection). I think we can do better still..

## Inline Assembly Method Using TEB
Using Inline ASM can be a headache and complicate the development process. Within offensive space it's a critical skill to have if you want to understand your actions, and capabilities. Link: https://github.com/killswitch-GUI/IsDebuggerPresent/tree/master/TEB-Recon

```
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
```
As you can see using "Winternl.h" we can easily link our structures needed and set up our for our PEB. Lets review whats taking place here:
 
1.  We define getPeb() as a PBEB structure.
2.  Using __asm, we can call on specific registers. It is often known that the Thread Execution Block (TEB) on x86 is stored in the FS register, we can use this to reference the PEB address: `FS:[0x30] Linear address of Process Environment Block (PEB)`
3.  Finally, use this PEB base address to populate our PPEB structure and reference the `pPeb->BeingDebugged` flag!

Finally, we achieved a 0/65 on Virus Total [TEB-Recon.exe](https://www.virustotal.com/#/file/5eeb534a6c1b78ebadba17dd84c792d3903fd3b3aab9d71fa608dab4dc0e4714/detection), significant defeat not really; interesting yes! 

 
