#include "main.h"

bool manual = false;

int main() {
	SetConsoleTitleA("MEMLA");
	CreateMutexA(0, 0, "Local\\MEMLA.exe");
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return -1;
	}

	if (PathFileExistsA("MirrorsEdge.exe") && !GetProcessInfoByName(L"MirrorsEdge.exe").th32ProcessID) {
		manual = true;

		STARTUPINFOA info = { 0 };
		info.cb = sizeof(STARTUPINFOA);
		PROCESS_INFORMATION pi;
		CreateProcessA(0, "MirrorsEdge.exe", 0, 0, 0, 0, 0, 0, &info, &pi);
	}

	SetTimer(0, 0, 500, (TIMERPROC)Scan);

	MSG msg;
	while (GetMessage(&msg, 0, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}

void Scan() {
	static DWORD pid = 0;

	PROCESSENTRY32 entry = GetProcessInfoByName(L"MirrorsEdge.exe");
	if (entry.th32ProcessID) {
		if (pid != entry.th32ProcessID) {
			HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
			if (process) {
				DWORD c1 = FindPattern(process, "\xE8\x00\x00\x00\x00\x83\xC4\x04\x39\x00\x00\x00\x00\x00\x74\x05", "x????xxxx?????xx"); // E8 ?? ?? ?? ?? 83 C4 04 39 ?? ?? ?? ?? ?? 74 05
				if (c1) {
					DWORD c2 = FindPattern(process, "\xE8\x00\x00\x00\x00\x83\xC4\x04\x39\x00\x00\x00\x00\x00\x74\x1E", "x????xxxx?????xx"); // E8 ?? ?? ?? ?? 83 C4 04 39 ?? ?? ?? ?? ?? 74 1E
					if (c2) {
						DWORD c3 = FindPattern(process, "\x68\xFE\x7F\x00\x00\x8D\x44\x24\x06", "xxxxxxxxx"); // 68 FE 7F 00 00 8D 44 24 06
						if (c3) {
							WriteProcessMemory(process, (void *)c1, "\x90\x90\x90\x90\x90", 5, 0);
							WriteProcessMemory(process, (void *)c2, "\x90\x90\x90\x90\x90", 5, 0);
							WriteProcessMemory(process, (void *)c3, "\x81\xC4\x04\x80\x00\x00\xC3", 7, 0);

							if (manual) {
								CloseHandle(process);
								exit(0);
							} else {
								pid = entry.th32ProcessID;
							}
						}
					}
				}

				CloseHandle(process);
			}
		}
	} else {
		pid = 0;
	}
}

PROCESSENTRY32 GetProcessInfoByName(wchar_t *exe_name) {
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, exe_name) == 0) {
				CloseHandle(snapshot);
				return entry;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return{ 0 };
}

DWORD FindPattern(HANDLE process, char *pattern, char *mask) {
	MODULEENTRY32 entry = { 0 };
	entry.dwSize = sizeof(MODULEENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
	Module32First(snapshot, &entry);
	CloseHandle(snapshot);

	char *buffer = (char *)malloc(entry.modBaseSize);
	ReadProcessMemory(process, entry.modBaseAddr, buffer, entry.modBaseSize, 0);

	DWORD length = entry.modBaseSize - strlen(mask);
	for (DWORD i = 0; i < length; ++i) {
		if (MaskCompare(&buffer[i], pattern, mask)) {
			free(buffer);
			return (DWORD)entry.modBaseAddr + i;
		}
	}

	free(buffer);
	return 0;
}

bool MaskCompare(const char *s1, const char *s2, char *mask) {
	for (; *mask; ++mask, ++s1, ++s2) {
		if (*mask == 'x' && *s1 != *s2) {
			return false;
		}
	}

	return true;
}