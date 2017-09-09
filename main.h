#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

void Scan();
PROCESSENTRY32 GetProcessInfoByName(wchar_t *exe_name);
DWORD FindPattern(HANDLE process, char *pattern, char *mask);
bool MaskCompare(const char *s1, const char *s2, char *mask);