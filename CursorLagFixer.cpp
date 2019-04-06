// CursorLagFixer.cpp
// Modifies SetCursor API to return NULL doing nothing.
// Sets the Window Handles HCURSOR to NULL.
//
// Usage: CursorLagFixer SomeProgram.exe

#include "pch.h"
#include <list>
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
// Note: linking to Psapi.lib is not necessary if the target system is Windows 7 or newer

using namespace std;

// 31 C0 - xor eax, eax
// C2 0400 - ret 0004
byte retNullPatch[] = {
	0x31, 0xC0,
	0xC2, 0x04,0x00
};


/*
 * Get File Name from a Path with or without extension
 */
std::string getFileName(std::string filePath, bool withExtension = true, char seperator = '\\')
{
	// Get last dot position
	std::size_t dotPos = filePath.rfind('.');
	std::size_t sepPos = filePath.rfind(seperator);

	if (sepPos != std::string::npos)
	{
		return filePath.substr(sepPos + 1, filePath.size() - (withExtension || dotPos != std::string::npos ? 1 : dotPos));
	}
	return "";
}


void GetAllWindowsFromProcessID(DWORD dwProcessID, vector <HWND> &vhWnds)
{
	// Find all hWnds (vhWnds) associated with a process id (dwProcessID)
	HWND hCurWnd = NULL;
	do
	{
		hCurWnd = FindWindowEx(NULL, hCurWnd, NULL, NULL);

		int windowTextLength = GetWindowTextLength(hCurWnd);

		// Ignore windows if invisible or missing a title
		if (IsWindowVisible(hCurWnd) && windowTextLength > 0) {
			DWORD windowProcessID = 0;
			GetWindowThreadProcessId(hCurWnd, &windowProcessID);
			if (windowProcessID == dwProcessID)
			{
				vhWnds.push_back(hCurWnd);  // add the found hCurWnd to the vector
				printf("\tFound hWnd %d\n", (int)hCurWnd);
			}
		}
	} while (hCurWnd != NULL);
}

DWORD PSAPI_EnumProcesses(list<DWORD>& listProcessIDs, DWORD dwMaxProcessCount)
{
	DWORD dwRet = NO_ERROR;
	listProcessIDs.clear();
	DWORD *pProcessIds = new DWORD[dwMaxProcessCount];
	DWORD cb = dwMaxProcessCount * sizeof(DWORD);
	DWORD dwBytesReturned = 0;

	// call PSAPI EnumProcesses
	if (::EnumProcesses(pProcessIds, cb, &dwBytesReturned))
	{
		// push returned process IDs into the output list
		const int nSize = dwBytesReturned / sizeof(DWORD);
		for (int nIndex = 0; nIndex < nSize; nIndex++)
		{
			listProcessIDs.push_back(pProcessIds[nIndex]);
		}
	}
	else
	{
		dwRet = ::GetLastError();
	}
	delete[]pProcessIds;
	return dwRet;
}

int main(int argc, char* argv[]) {
	if (argc == 1) {
		printf("Usage: %s ProgramName.exe", argv[0]);
		Sleep(5000);
		return 0;
	}

	char* targetProcessName = argv[1];

	list<DWORD> listProcessIDs;
	const DWORD dwMaxProcessCount = 1024; // If you have more processes than this, wtf.
	DWORD dwRet = PSAPI_EnumProcesses(listProcessIDs, dwMaxProcessCount);
	if (NO_ERROR == dwRet)
	{
		const list<DWORD>::const_iterator end = listProcessIDs.end();
		list<DWORD>::const_iterator iter = listProcessIDs.begin();
		for (; iter != end; ++iter)
		{
			DWORD dwProcessID = *iter;
			
			// Pass dwProcessID to OpenProcess and further get more process info by using the returned process handle 
			HANDLE hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
				false,
				dwProcessID
			);

			if (NULL == hProcess) {
				continue;
			}

			

			char processFilename[MAX_PATH];
			GetModuleFileNameEx(hProcess, NULL, processFilename, MAX_PATH);
			string processName = getFileName(processFilename);
			
			if (processName.compare(targetProcessName) != 0) {
				continue;
			}

			printf("Process Found ID: %u FilePath: %s\n", dwProcessID, processFilename);

			// Get current window handles for process id.
			printf("\tFinding windows\n");
			vector<HWND> windowHandles;
			windowHandles.clear();
			GetAllWindowsFromProcessID(dwProcessID, windowHandles);

			printf("\tWindows found: %u.\n", windowHandles.size());
			printf("\tSetting HCURSOR to NULL\n");
			for (vector<HWND>::iterator it = windowHandles.begin(); it != windowHandles.end(); ++it) {
				SetClassLongPtrA(*it, GCLP_HCURSOR, NULL);
			}
			


			// Get a list of all the modules in this process.
			HMODULE hMods[1024];
			DWORD cbNeeded;

			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				for (int j = 0; j < (int)(cbNeeded / sizeof(HMODULE)); j++)
				{
					TCHAR szModName[MAX_PATH];

					// Get the full path to the module's file.

					if (GetModuleFileNameEx(hProcess, hMods[j], szModName, MAX_PATH))
					{
						string moduleName = getFileName(szModName);
						if (_strcmpi(moduleName.c_str(),"USER32.dll") == 0) {
							// Print the module name and handle value.
							printf("\tGetting SetCursor address.\n");
							FARPROC setCursorAddress = GetProcAddress(hMods[j], "SetCursor");
							if (setCursorAddress == NULL) {
								printf("\tUnable to get SetCursor Address\n");
								continue;
							}

							printf("\tDisabling SetCursor at %016X\n", (unsigned int)setCursorAddress);

							// Set memory protection so we can write our patch to disable SetCursor.
							DWORD oldProtection;
							if (!VirtualProtect(
								setCursorAddress,
								sizeof(retNullPatch),
								PAGE_EXECUTE_READWRITE,
								&oldProtection
							)) {
								printf("\tUnable to set memory protection to PAGE_EXECUTE_READWRITE\n.");
								continue;
							}

							
							// Write the patch to return null from setCursor.
							WriteProcessMemory(hProcess, (void*)(setCursorAddress), retNullPatch, sizeof(retNullPatch), NULL);

							// Restore previous memory protection.
							VirtualProtect(
								setCursorAddress,
								sizeof(retNullPatch),
								oldProtection,
								&oldProtection
							);

							// We have applied all the patches we need lets get out of this loop.
							break;
						}
					}
				}
			}

			// Release the handle to the process.
			CloseHandle(hProcess);
		}
	}
	else
	{
		printf("PSAPI_GetProcessesList failed. Error: %u\n", dwRet);
		return dwRet;
	}


	printf("Done.\n");
	Sleep(3000);
	return 0;
}