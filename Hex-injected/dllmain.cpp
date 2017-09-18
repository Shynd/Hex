#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <atlstr.h>

// MS Detours...
#pragma comment(lib, "detours.lib")
#include <detours.h>

/*
 * CreateFileW(
   _In_ LPCWSTR lpFileName,
   _In_ DWORD dwDesiredAccess,
   _In_ DWORD dwShareMode,
   _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
   _In_ DWORD dwCreationDisposition,
   _In_ DWORD dwFlagsAndAttributes,
   _In_opt_ HANDLE hTemplateFile
);
*/

typedef HANDLE(WINAPI *CREATEFILEW)(
	LPCWSTR					lpFileName,
	DWORD					dwDesiredAccess,
	DWORD					dwShareMode,
	LPSECURITY_ATTRIBUTES	lpSecurityAttributes,
	DWORD					dwCreationDisposition,
	DWORD					dwFlagsAndAttributes,
	HANDLE					h_template_file_handle
	);
CREATEFILEW OrigCreateFileW = NULL;

HANDLE WINAPI HookCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							  LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
							  HANDLE hTemplateFile) {
	std::wcout << "CreateFileW: " << lpFileName << std::endl;

	// Before calling the original function, we want to
	// check whether the file accessed is a background image for a beatmap.
	// And if so, change the 'lpFileName' with a custom path.
	// TODO: This hack is ugly as all hell, do it better.
	LPCWSTR replacement = L"C:\\Users\\HK\\Pictures\\listen.jpg";
	std::string jpgExt = ".jpg";
	std::string jpegExt = ".jpeg";
	std::string pngExt = "'.png";
	std::string fileName = CW2A(lpFileName);

	if (fileName.find(jpgExt) != std::string::npos || fileName.find(pngExt) != std::string::npos || fileName.find(jpgExt) != std::string::npos) {
		//std::wcout << "Inside HookCreateFileW: " << lpFileName << std::endl;
		std::wcout << "Changing '" << lpFileName << "' into '" << replacement << "'\n";
		lpFileName = replacement;
	}

	// Call the original function.
	return OrigCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
						   dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void InstallHooks() {
	// Get Kernel32.
	HMODULE hmodKernel32 = GetModuleHandle(TEXT("KERNEL32.dll"));

	OrigCreateFileW = (CREATEFILEW)GetProcAddress(hmodKernel32, "CreateFileW");

	// Install the hooks.
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// CreateFileW hook
	std::cout << "Attaching our CreateFileW hook.\n";
	DetourAttach(&(PVOID&)OrigCreateFileW, HookCreateFileW);

	DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		std::cout << "Installing hooks.\n";
		InstallHooks();
		break;
	default:
		break;
	}

	return TRUE;
}