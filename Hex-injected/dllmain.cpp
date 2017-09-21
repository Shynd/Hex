#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <atlstr.h>

// MS Detours...
#pragma comment(lib, "detours.lib")
#include <detours.h>

LPCWSTR ReplacementPath;
bool ShowConsole = false;

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
	//std::wcout << "CreateFileW: " << lpFileName << std::endl;

	// Before calling the original function, we want to
	// check whether the file accessed is a background image for a beatmap.
	// And if so, change the 'lpFileName' with a custom path.
	// TODO: This hack is ugly as all hell, do it better.
	
	if (ReplacementPath != nullptr) {
		std::string jpgExt = ".jpg";
		std::string jpegExt = ".jpeg";
		std::string pngExt = "'.png";
		std::string fileName = CW2A(lpFileName);

		if (fileName.find(jpgExt) != std::string::npos || fileName.find(pngExt) != std::string::npos || fileName.find(jpgExt) != std::string::npos) {
			//std::wcout << "Inside HookCreateFileW: " << lpFileName << std::endl;
			std::wcout << "Changing '" << lpFileName << "' into '" << ReplacementPath << "'\n";
			lpFileName = ReplacementPath;
		}
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

wchar_t *ConvertCharArrayToLPCWSTR(const char* charArray) {
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

void ChangeBackgroundImage() {
	char filename[MAX_PATH];
	OPENFILENAME ofn;
	ZeroMemory(&filename, sizeof(filename));
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFilter = "Jpg Files\0*.jpg\0Any File\0*.*\0";
	ofn.lpstrFile = filename;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "Select an image";
	ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;

	if (GetOpenFileNameA(&ofn))
	{
		ReplacementPath = ConvertCharArrayToLPCWSTR(filename);
	}
	else
	{
		switch (CommDlgExtendedError())
		{
		case CDERR_DIALOGFAILURE: std::cout << "CDERR_DIALOGFAILURE\n";   break;
		case CDERR_FINDRESFAILURE: std::cout << "CDERR_FINDRESFAILURE\n";  break;
		case CDERR_INITIALIZATION: std::cout << "CDERR_INITIALIZATION\n";  break;
		case CDERR_LOADRESFAILURE: std::cout << "CDERR_LOADRESFAILURE\n";  break;
		case CDERR_LOADSTRFAILURE: std::cout << "CDERR_LOADSTRFAILURE\n";  break;
		case CDERR_LOCKRESFAILURE: std::cout << "CDERR_LOCKRESFAILURE\n";  break;
		case CDERR_MEMALLOCFAILURE: std::cout << "CDERR_MEMALLOCFAILURE\n"; break;
		case CDERR_MEMLOCKFAILURE: std::cout << "CDERR_MEMLOCKFAILURE\n";  break;
		case CDERR_NOHINSTANCE: std::cout << "CDERR_NOHINSTANCE\n";     break;
		case CDERR_NOHOOK: std::cout << "CDERR_NOHOOK\n";          break;
		case CDERR_NOTEMPLATE: std::cout << "CDERR_NOTEMPLATE\n";      break;
		case CDERR_STRUCTSIZE: std::cout << "CDERR_STRUCTSIZE\n";      break;
		case FNERR_BUFFERTOOSMALL: std::cout << "FNERR_BUFFERTOOSMALL\n";  break;
		case FNERR_INVALIDFILENAME: std::cout << "FNERR_INVALIDFILENAME\n"; break;
		case FNERR_SUBCLASSFAILURE: std::cout << "FNERR_SUBCLASSFAILURE\n"; break;
		default: std::cout << "You cancelled.\n";
		}
	}
}

DWORD WINAPI OnDllAttach(LPVOID base) {
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	std::cout << "Installing hooks.\n";
	InstallHooks();

	// Done setting up, make the user aware.
	std::cout << "Done setting up! Press 'Home' in order to bring up the image selection dialog!\n";
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	while (true) {
		if (GetAsyncKeyState(0x24 /* Home */)) {
			ChangeBackgroundImage();
		}
		else if (GetAsyncKeyState(0x23 /* End */)) {
			if (ShowConsole) {
				ShowWindow(GetConsoleWindow(), SW_HIDE);
				ShowConsole = false;
			}
			else {
				ShowWindow(GetConsoleWindow(), SW_SHOW);
				ShowConsole = true;
			}
		}

		Sleep(500);
	}

	return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hInstDll, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hInstDll);
		CreateThread(nullptr, 0, OnDllAttach, hInstDll, 0, nullptr);
		break;
	default:
		break;
	}

	return TRUE;
}