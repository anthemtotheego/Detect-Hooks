#include <windows.h>
#include <stdio.h>

#include "beacon.h"
#include "detect-hooks.h"

/*BOF Entry Point*/
void go(char* args, int length) {//Attempts to detect userland hooks by AV/EDR

    //Variables
	size_t size = 65535;
	char* returnData = (char*)intAlloc(size);
	memset(returnData, 0, size);
	unsigned int returnDataLen;
	PDWORD functionAddress = (PDWORD)0;
	
	//Get ntdll base address
	HMODULE libraryBase = LoadLibrary("ntdll.dll");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	//Locate export address table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	//Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);
	
	//Iterate through exported functions of ntdll
	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		//Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;

		//Resolve exported function address
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

		//Syscall stubs start with these bytes
		char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		//Only interested in Nt|Zw functions
		if (MSVCRT$strncmp(functionName, (char*)"Nt", 2) == 0 || MSVCRT$strncmp(functionName, (char*)"Zw", 2) == 0)
		{
			//If known false positive ignore otherwise print hooked API
			if (MSVCRT$strncmp(functionName, (char*)"NtGetTickCount", 14) == 0 || MSVCRT$strncmp(functionName, (char*)"NtQuerySystemTime", 17) == 0 || MSVCRT$strncmp(functionName, (char*)"NtdllDefWindowProc_A", 20) == 0 || MSVCRT$strncmp(functionName, (char*)"NtdllDefWindowProc_W", 20) == 0 || MSVCRT$strncmp(functionName, (char*)"NtdllDialogWndProc_A", 20) == 0 || MSVCRT$strncmp(functionName, (char*)"NtdllDialogWndProc_W", 20) == 0 || MSVCRT$strncmp(functionName, (char*)"ZwQuerySystemTime", 17) == 0) 	
			{	
				//Ignore false positives
			}
			else {
				// Check if the first 4 instructions of the exported function are the same as the sycall's prologue
				if (MSVCRT$memcmp(functionAddress, syscallPrologue, 4) != 0) {
				
					//Convert versions/buildNumber to string
					returnDataLen = MSVCRT$_snprintf(NULL, 0, "%s\n", functionName);
					MSVCRT$_snprintf(returnData + MSVCRT$strlen(returnData), returnDataLen + 1, "%s\n", functionName);
					
					//If you want to return the function address as well instead
					/*returnDataLen = MSVCRT$_snprintf(NULL, 0, "%s %p\n", functionName, functionAddress);
					MSVCRT$_snprintf(returnData + MSVCRT$strlen(returnData), returnDataLen + 1, "%s %p\n", functionName, functionAddress);*/
					
				}
			}
		}
	}

	if (MSVCRT$strlen(returnData) == 0)
	{
		//No hooks found
		BeaconPrintf(CALLBACK_OUTPUT, "\nNo Hooks Found\n");
	}
	else
	{
		//Send hook output back to CS
		BeaconPrintf(CALLBACK_OUTPUT, "\n%s\n", returnData);
	}
}