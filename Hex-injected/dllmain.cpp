#include <Windows.h>
#include <stdio.h>
#include <iostream>

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