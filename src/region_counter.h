#ifndef REGION_COUNTER_H
#define REGION_COUNTER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_REGIONS 32

#pragma pack(push, 1)
typedef struct {
    unsigned char unk1[16];
    char          name[32];
    DWORD         max_kills;
    unsigned char boss_flag;
    unsigned char pad[3];
    DWORD         current_kills;
    unsigned char region_id;
    unsigned char pad2[3];
} SacredRegionEntry;
#pragma pack(pop)

void LogMsg(const char* fmt, ...);
void InitRegionCounter(void);
void ShutdownRegionCounter(void);

#ifdef __cplusplus
}
#endif

#endif // REGION_COUNTER_H
