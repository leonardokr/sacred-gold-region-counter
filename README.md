# Sacred Gold Persistent Region Counter Mod

Non-invasive runtime mod for **Sacred Gold** (v2.28) that persists the regional enemy kill counters across sessions, teleports, and zone transitions.

---

## The Problem in Vanilla Sacred

In *Sacred Gold / Sacred Underworld*, each geographical territory features an internal kill countdown designed to trigger unique **Region Bosses** when the counter reaches 0.

However, in vanilla game sessions:
1. Progress is purely kept in volatile memory and is **never written to savegames (`.sav`/`.pax`)**.
2. Stepping across a region border causes the engine to reset the counter back to its maximum.
3. Using portals, entering caves/towns, or saving and quitting wipes 100% of the session kill progress.

---

## How It Works

- **Zero Binary Modification:** `Sacred.exe` on disk remains untouched.
- **Persistent Storage:** Progress is saved automatically to `save\region_kills.ini` keyed by hero name.
- **Mod Loader Architecture:** Runs as a plugin loaded by `sacred-gold-mod-loader`.

### Storage Format (`save\region_kills.ini`)

```ini
[Hero_Aria]
Region_1 = 4320
Region_2 = 6190
Region_12 = 850
```

---

## Prerequisites

This mod requires [sacred-gold-mod-loader](https://github.com/leonardokr/sacred-gold-mod-loader) installed in your Sacred Gold directory (`version.dll`).

---

## Installation

1. Make sure **Sacred Gold Mod Loader** is installed in your game folder.
2. Download `sacred-region-counter.dll` from the latest [Releases](../../releases) tab.
3. Place `sacred-region-counter.dll` inside the `mods/` folder in your game directory:
   ```
   Sacred Gold/
   ├── Sacred.exe
   ├── version.dll                 <- sacred-gold-mod-loader
   └── mods/
       └── sacred-region-counter.dll
   ```
4. Launch the game normally via Steam, GOG, or `Sacred.exe`.
5. Kill tallies will automatically save to `save\region_kills.ini`.

---

## Building from Source

Requirements:
- Visual Studio 2022 (MSVC x86 / 32-bit compiler tools)

Run:
```cmd
src\build.bat
```
The compiled DLL will be placed in `bin\sacred-region-counter.dll` and root `sacred-region-counter.dll`.
