#include "region_counter.h"
#include <time.h>

static char g_ini_path[MAX_PATH] = {0};
static CRITICAL_SECTION g_cs;
static volatile BOOL g_running = FALSE;
static HANDLE g_hThread = NULL;

void LogMsg(const char* fmt, ...) {
    EnterCriticalSection(&g_cs);
    FILE* f = fopen("sacred_region_counter.log", "a");
    if (f) {
        time_t rawtime;
        struct tm* timeinfo;
        char time_buf[32];
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        if (timeinfo) {
            strftime(time_buf, sizeof(time_buf), "%H:%M:%S", timeinfo);
        } else {
            snprintf(time_buf, sizeof(time_buf), "--:--:--");
        }

        fprintf(f, "[%s] ", time_buf);
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

static void InitIniPath(void) {
    char exe_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_path, sizeof(exe_path))) {
        char* last_slash = strrchr(exe_path, '\\');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(g_ini_path, sizeof(g_ini_path), "%s\\save\\region_kills.ini", exe_path);
            return;
        }
    }
    snprintf(g_ini_path, sizeof(g_ini_path), "save\\region_kills.ini");
}

static void EnsureSaveDirectoryExists(void) {
    CreateDirectoryA("save", NULL);
}

static DWORD LoadRegionProgress(unsigned char region_id, DWORD default_max) {
    char key[64];
    snprintf(key, sizeof(key), "Region_%u", (unsigned int)region_id);

    int saved = GetPrivateProfileIntA("Regions", key, -1, g_ini_path);
    if (saved < 0 || (DWORD)saved > default_max) {
        return default_max;
    }
    return (DWORD)saved;
}

static void SaveRegionProgress(unsigned char region_id, const char* name, DWORD remaining_kills) {
    EnterCriticalSection(&g_cs);
    EnsureSaveDirectoryExists();

    char key_kills[64];
    snprintf(key_kills, sizeof(key_kills), "Region_%u", (unsigned int)region_id);

    char val_kills[32];
    snprintf(val_kills, sizeof(val_kills), "%u", remaining_kills);

    WritePrivateProfileStringA("Regions", key_kills, val_kills, g_ini_path);

    if (name && name[0] != '\0') {
        char key_name[64];
        snprintf(key_name, sizeof(key_name), "Region_%u_Name", (unsigned int)region_id);
        WritePrivateProfileStringA("Regions", key_name, name, g_ini_path);
    }
    LeaveCriticalSection(&g_cs);
}

static SacredRegionEntry* LocateRegionTable(void) {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return NULL;

    unsigned char* base = (unsigned char*)hExe;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    unsigned char* text_start = NULL;
    DWORD text_size = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            text_start = base + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!text_start || text_size < 1000) {
        text_start = base + 0x1000;
        text_size = 0x500000;
    }

    // Pattern 1: push 0x008EB6E8 ("cStatsManager::Instance() create[%p]")
    // Byte sequence: 68 E8 B6 8E 00
    // Followed within 40 bytes by: B8 [ptr] B9 20 00 00 00
    const unsigned char pat1[] = { 0x68, 0xE8, 0xB6, 0x8E, 0x00 };
    for (DWORD i = 0; i < text_size - 60; i++) {
        if (memcmp(text_start + i, pat1, sizeof(pat1)) == 0) {
            unsigned char* sub = text_start + i;
            for (int j = 0; j < 40; j++) {
                if (sub[j] == 0xB8 && sub[j+5] == 0xB9 && sub[j+6] == 0x20 && sub[j+7] == 0x00 && sub[j+8] == 0x00 && sub[j+9] == 0x00) {
                    DWORD target_addr = *(DWORD*)(sub + j + 1);
                    if (target_addr > 0x00400000 && target_addr < 0x02000000) {
                        SacredRegionEntry* pTable = (SacredRegionEntry*)(target_addr - 0x38);
                        LogMsg("[SCAN] Located region table via cStatsManager signature at 0x%p (target=0x%08X)", pTable, target_addr);
                        return pTable;
                    }
                }
            }
        }
    }

    // Pattern 2: push 0x008EB738 ("initRegionKill(%d,%d,%s)")
    // Byte sequence: 68 38 B7 8E 00
    const unsigned char pat2[] = { 0x68, 0x38, 0xB7, 0x8E, 0x00 };
    for (DWORD i = 0; i < text_size - 60; i++) {
        if (memcmp(text_start + i, pat2, sizeof(pat2)) == 0) {
            unsigned char* sub = text_start + i;
            // Search backward 40 bytes for lea eax, [esi + offset] (8D 86 xx xx xx xx)
            for (int j = -40; j < 0; j++) {
                if (sub + j >= text_start && sub[j] == 0x8D && sub[j+1] == 0x86) {
                    DWORD offset = *(DWORD*)(sub + j + 2);
                    if (offset > 0x00400000 && offset < 0x02000000) {
                        SacredRegionEntry* pTable = (SacredRegionEntry*)(offset - 0x10);
                        LogMsg("[SCAN] Located region table via initRegionKill signature at 0x%p", pTable);
                        return pTable;
                    }
                }
            }
        }
    }

    return NULL;
}

static DWORD WINAPI RegionWatchdogThread(LPVOID lpParam) {
    (void)lpParam;
    LogMsg("[WATCHDOG] Thread initialized. Awaiting game startup and memory decryption...");

    SacredRegionEntry* regions = NULL;
    int attempts = 0;

    while (g_running && !regions && attempts < 90) {
        Sleep(1000);
        regions = LocateRegionTable();
        attempts++;
    }

    if (!regions) {
        LogMsg("[ERROR] Failed to locate region table in RAM after %d seconds.", attempts);
        return 0;
    }

    LogMsg("[SUCCESS] Region table attached at 0x%p. Activating active kill tracking and reset protection.", regions);

    DWORD last_known_kills[MAX_REGIONS] = {0};
    BOOL region_initialized[MAX_REGIONS] = {FALSE};

    while (g_running) {
        Sleep(500); // 2Hz polling: negligible CPU overhead (< 0.01%)

        for (int i = 0; i < MAX_REGIONS; i++) {
            SacredRegionEntry* r = &regions[i];

            DWORD max_k = r->max_kills;
            if (max_k < 100 || max_k > 50000) {
                continue;
            }

            DWORD cur = r->current_kills;
            unsigned char id = r->region_id;

            if (!region_initialized[i]) {
                region_initialized[i] = TRUE;
                DWORD saved = LoadRegionProgress(id, max_k);

                if (saved > 0 && saved < max_k) {
                    r->current_kills = saved;
                    cur = saved;
                    LogMsg("[RESTORE] Region %u ('%s'): Restored saved %u kills remaining (vanilla was %u)",
                           (unsigned int)id, r->name, saved, max_k);
                } else {
                    LogMsg("[INIT] Region %u ('%s'): Active with %u/%u kills remaining",
                           (unsigned int)id, r->name, cur, max_k);
                }
                last_known_kills[i] = cur;
                continue;
            }

            if (cur < last_known_kills[i]) {
                DWORD delta = last_known_kills[i] - cur;
                last_known_kills[i] = cur;
                SaveRegionProgress(id, r->name, cur);
                LogMsg("[KILL] Region %u ('%s'): %u kills remaining (-%u)",
                       (unsigned int)id, r->name, cur, delta);
            }
            else if (cur > last_known_kills[i]) {
                if (last_known_kills[i] > 0 && cur == max_k) {
                    r->current_kills = last_known_kills[i];
                    LogMsg("[GUARD] Blocked vanilla reset in Region %u ('%s')! Enforced %u kills (prevented reset to %u)",
                           (unsigned int)id, r->name, last_known_kills[i], max_k);
                } else {
                    last_known_kills[i] = cur;
                }
            }
        }
    }

    LogMsg("[WATCHDOG] Thread terminating cleanly.");
    return 0;
}

void InitRegionCounter(void) {
    InitializeCriticalSection(&g_cs);
    DeleteFileA("sacred_region_counter.log");
    InitIniPath();
    LogMsg("--- Sacred Gold Persistent Region Counter v1.1.0 ---");
    LogMsg("Target ini storage: %s", g_ini_path);

    g_running = TRUE;
    g_hThread = CreateThread(NULL, 0, RegionWatchdogThread, NULL, 0, NULL);
    if (!g_hThread) {
        LogMsg("[ERROR] Failed to spawn Watchdog thread! (GetLastError: %lu)", GetLastError());
    }
}

void ShutdownRegionCounter(void) {
    if (g_running) {
        g_running = FALSE;
        if (g_hThread) {
            WaitForSingleObject(g_hThread, 1500);
            CloseHandle(g_hThread);
            g_hThread = NULL;
        }
    }
    LogMsg("Sacred Region Counter shut down cleanly.");
    DeleteCriticalSection(&g_cs);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        InitRegionCounter();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        ShutdownRegionCounter();
    }
    return TRUE;
}
