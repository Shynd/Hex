#include <Windows.h>
#include <stdio.h>
#include <iostream>

// MS Detours...
#pragma comment(lib, "detours.lib")
#include <detours.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		//InstallHooks();
		break;
	default:
		break;
	}

	return TRUE;
}