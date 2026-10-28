// Lab canary. where.exe imports version.dll, and that DLL is not a KnownDLL,
// so a copy of where.exe loads this file from its own directory.
// The three exports call the real System32 copy so the process can finish
// starting. DllMain does not write a file. The marker is staged first.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static HMODULE real_version(void) {
    static HMODULE mod = NULL;
    if (mod) {
        return mod;
    }
    wchar_t path[MAX_PATH];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 16) {
        return NULL;
    }
    wcscat_s(path, MAX_PATH, L"\\version.dll");
    mod = LoadLibraryW(path);
    return mod;
}

static void say_loaded(void) {
    wchar_t canary[160];
    DWORD got = GetEnvironmentVariableW(L"LAB_TRIDENT_CANARY", canary, 160);
    if (got == 0 || got >= 160) {
        wcscpy_s(canary, 160, L"LAB-TRIDENT-SIDELOAD");
    }
    wchar_t line[240];
    if (swprintf_s(line, 240, L"%s version.dll loaded from the EXE directory\r\n", canary) < 0) {
        return;
    }
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == NULL || out == INVALID_HANDLE_VALUE) {
        return;
    }
    char utf8[320];
    int len = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), NULL, NULL);
    if (len > 1) {
        DWORD wrote = 0;
        WriteFile(out, utf8, (DWORD)(len - 1), &wrote, NULL);
    }
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        say_loaded();
    }
    return TRUE;
}

extern "C"
DWORD WINAPI LabSize(DWORD flags, LPCWSTR name, LPDWORD handle) {
    HMODULE mod = real_version();
    if (!mod) {
        return 0;
    }
    typedef DWORD (WINAPI *Fn)(DWORD, LPCWSTR, LPDWORD);
    Fn fn = (Fn)GetProcAddress(mod, "GetFileVersionInfoSizeExW");
    if (!fn) {
        return 0;
    }
    return fn(flags, name, handle);
}

extern "C"
BOOL WINAPI LabInfo(DWORD flags, LPCWSTR name, DWORD handle, DWORD len, LPVOID data) {
    HMODULE mod = real_version();
    if (!mod) {
        return FALSE;
    }
    typedef BOOL (WINAPI *Fn)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    Fn fn = (Fn)GetProcAddress(mod, "GetFileVersionInfoExW");
    if (!fn) {
        return FALSE;
    }
    return fn(flags, name, handle, len, data);
}

extern "C"
BOOL WINAPI LabQuery(LPCVOID block, LPCWSTR sub, LPVOID *buf, PUINT buflen) {
    HMODULE mod = real_version();
    if (!mod) {
        return FALSE;
    }
    typedef BOOL (WINAPI *Fn)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
    Fn fn = (Fn)GetProcAddress(mod, "VerQueryValueW");
    if (!fn) {
        return FALSE;
    }
    return fn(block, sub, buf, buflen);
}
