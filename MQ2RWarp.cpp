// MQ2RWarp.cpp :: Warp, Fade, Zome, and Gate functions
// v1.00 :: TheDroidUrLookingFor - 06/05/2024
// -- Updated code to compile on latest version of MQ
// -- Wrote an AoB scan to find MoveLocalPlayerToSafeCoords
// -- Wrote an AoB scan to find DoTheZone
// -- Added a command to update offsets on the fly.
//
#include <mq/Plugin.h>
#include <TlHelp32.h>
#include <iostream>
#include <Psapi.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <string>
#include <intrin.h>
#include "Sig.h"

PreSetup("MQ2RWarp");
PLUGIN_VERSION(0.1);

#undef ExactLocation
#undef zWarp
#undef DoWarp
#undef Warp
#undef SafeYLoc
#undef SafeXLoc
#undef SafeZLoc
#undef GateBind
#undef ZoneShift
#undef ZoneToGoTo

DWORD BASE_ADDRESS = 0x5D0000;
DWORD ADDRESS_SAFE_Y = 0x9DFB3C;
DWORD ADDRESS_SAFE_X = 0x9DFB40;
DWORD ADDRESS_SAFE_Z = 0x9DFB44;

DWORD CDisplay__MoveLocalPlayerToSafeCoords = 0x0;
DWORD LocalCEverQuest__DoTheZone = 0x0;

// Function prototypes
VOID AoBScan();
VOID DoAoBScan(PSPAWNINFO pChar, PCHAR szLine);
VOID DoShowOffsets(PSPAWNINFO pChar, PCHAR szLine);
VOID DoWarp(float y, float x, float z);
VOID Warp(PSPAWNINFO pChar, PCHAR szLine);
VOID zWarp(PSPAWNINFO pChar, PCHAR szLine);
VOID ExactLocation(PSPAWNINFO pChar, PCHAR szLine);
VOID GateBind(PSPAWNINFO pChar, PCHAR szLine);
VOID ZoneShift(PSPAWNINFO pChar, PCHAR szLine);
VOID doFade(PSPAWNINFO pChar, PCHAR szLine);
VOID waypoint(PSPAWNINFO pChar, PCHAR szLine);

VOID ExactLocation(PSPAWNINFO pChar, PCHAR szLine)
{
	CHAR LocMsg[MAX_STRING] = { 0 };
	sprintf_s(LocMsg, "Your location is %3.6f, %3.6f, %3.6f", pChar->Y, pChar->X, pChar->Z);
	WriteChatColor(LocMsg);
}

VOID zWarp(PSPAWNINFO pChar, PCHAR szLine)
{
	CHAR Z[MAX_STRING] = { 0 };
	GetArg(Z, szLine, 1);
	float MyY = pChar->Y;
	float MyX = pChar->X;

	if (Z[0] == 0) {
		WriteChatColor("Usage: /zwarp <dist>", CONCOLOR_RED);
		return;
	}

	float NewZ = pChar->Z + (FLOAT)atof(Z);
	DoWarp(MyY, MyX, NewZ);
}

VOID Warp(PSPAWNINFO pChar, PCHAR szLine)
{
	static float LastY, LastX, LastZ;
	bRunNextCommand = TRUE;
	PSPAWNINFO psTarget = NULL;
	PZONEINFO Zone = (PZONEINFO)pZoneInfo;
	CHAR command[MAX_STRING];
	CHAR Y[MAX_STRING], X[MAX_STRING], Z[MAX_STRING];

	GetArg(command, szLine, 1);
	GetArg(Y, szLine, 2);
	GetArg(X, szLine, 3);
	GetArg(Z, szLine, 4);

	if (_stricmp(command, "succor") != 0 && _stricmp(command, "loc") != 0 &&
		_stricmp(command, "last") != 0 && _stricmp(command, "target") != 0 &&
		_stricmp(command, "dir") != 0 && _stricmp(command, "t") != 0 && _stricmp(command, "s") != 0 && _stricmp(command, "wp") != 0) {
		WriteChatColor("Usage: /warp <succor|last|loc <y x z>|dir <dist>|target|wp name>", CONCOLOR_RED);
		return;
	}

	if (!_stricmp(command, "target") || !_stricmp(command, "t")) {
		if (pTarget) {
			psTarget = (PSPAWNINFO)pTarget;
		}
		if (!psTarget) {
			WriteChatColor("You must have a target for /warp target.", CONCOLOR_RED);
			return;
		}
		float TargetZ = (float)psTarget->Z;
		float TargetY = (float)psTarget->Y;
		float TargetX = (float)psTarget->X;
		LastY = TargetY;
		LastX = TargetX;
		LastZ = TargetZ;
		DoWarp(TargetY, TargetX, TargetZ);
	}
	else if (!_stricmp(command, "succor") || !_stricmp(command, "s")) {
		static float north = 0;
		((PSPAWNINFO)pCharSpawn)->Heading = north;
		DWORD MLPTSC = CDisplay__MoveLocalPlayerToSafeCoords;
		__asm call dword ptr[MLPTSC];
		return;
	}
	else if (!_stricmp(command, "loc")) {
		if (Y[0] == 0 || X[0] == 0 || Z[0] == 0) {
			WriteChatColor("You must provide <y> <x> <z> if going to a location.", CONCOLOR_RED);
			return;
		}
		LastY = (float)atof(Y);
		LastX = (float)atof(X);
		LastZ = (float)atof(Z);
		DoWarp(LastY, LastX, LastZ);
	}
	else if (!_stricmp(command, "last")) {
		if (LastY == 0 || LastX == 0 || LastZ == 0) {
			WriteChatColor("You must have warped before to use this command!", CONCOLOR_RED);
			return;
		}
		DoWarp(LastY, LastX, LastZ);
	}
	else if (!_stricmp(command, "dir")) {
		if (Y[0] == 0) {
			WriteChatColor("You MUST provide <dist> if going in your current direction.", CONCOLOR_RED);
			return;
		}
		FLOAT angle = (FLOAT)(pChar->Heading * 0.0123);
		FLOAT dist = (FLOAT)atof(Y);
		DoWarp(pChar->Y + (FLOAT)(dist * cos(angle)), pChar->X + (FLOAT)(dist * sin(angle)), pChar->Z);
	}
	else {
		CHAR szLoc[MAX_STRING] = { 0 };
		CHAR szName[MAX_STRING] = { 0 };
		CHAR WaypointsINI[MAX_STRING] = { 0 };
		CHAR szBuf[MAX_STRING] = { 0 };
		CHAR szHeading[MAX_STRING] = { 0 };
		CHAR szDestWarpX[MAX_STRING] = { 0 };
		CHAR szDestWarpY[MAX_STRING] = { 0 };
		CHAR szDestWarpZ[MAX_STRING] = { 0 };
		CHAR szMsg[MAX_STRING] = { 0 };

		sprintf_s(WaypointsINI, "%s\\waypoints.ini", gPathMQRoot);
		GetArg(szName, szLine, 2);

		if (!_strnicmp(szName, "", 1)) {
			WriteChatColor("You didn't specify a waypoint.", COLOR_LIGHTGREY);
		}
		else {
			GetPrivateProfileString(Zone->ShortName, szName, "", szLoc, MAX_STRING, WaypointsINI);

			if (!_strnicmp(szLoc, "", 1)) {
				sprintf_s(szMsg, "Waypoint \'%s\' does not exist.", szName);
				WriteChatColor(szMsg, COLOR_LIGHTGREY);
			}
			else {
				GetArg(szDestWarpX, szLoc, 2);
				GetArg(szDestWarpY, szLoc, 1);
				GetArg(szDestWarpZ, szLoc, 3);

				GetArg(szBuf, szLoc, 4);
				GetArg(szHeading, szBuf, 1, 0, 0, 0, ':');
				DoWarp((float)atof(szDestWarpY), (float)atof(szDestWarpX), (float)atof(szDestWarpZ));
			}
		}
	}
}

VOID waypoint(PSPAWNINFO pChar, PCHAR szLine)
{
	PZONEINFO Zone = (PZONEINFO)pZoneInfo;
	CHAR WaypointsINI[MAX_STRING] = { 0 };
	CHAR szTemp[10] = { 0 };
	CHAR szData[MAX_STRING] = { 0 };
	CHAR szDesc[MAX_STRING] = { 0 };
	CHAR szName[MAX_STRING] = { 0 };
	CHAR szCommand[MAX_STRING] = { 0 };
	CHAR szBuffer[MAX_STRING] = { 0 };
	CHAR szMsg[MAX_STRING] = { 0 };
	CHAR WaypointList[MAX_STRING * 10] = { 0 };
	PCHAR pWaypointList = WaypointList;
	CHAR szKey[MAX_STRING] = { 0 };
	CHAR szValue[MAX_STRING] = { 0 };

	sprintf_s(WaypointsINI, "%s\\waypoints.ini", gPathMQRoot);
	GetArg(szCommand, szLine, 1);

	if (szCommand[0] == 0 || !_stricmp(szCommand, "help")) {
		WriteChatColor("Usage: /wp add <name> <description>", CONCOLOR_RED);
		WriteChatColor("       /wp del <name>", CONCOLOR_RED);
		WriteChatColor("       /wp list", CONCOLOR_RED);
		return;
	}

	if (!_stricmp(szCommand, "add")) {
		GetArg(szName, szLine, 2);
		GetArg(szDesc, szLine, 3);

		if (szName[0] == 0) {
			WriteChatColor("Usage: /wp add <name> <description>", CONCOLOR_RED);
			return;
		}

		if (szDesc[0] == 0) {
			WriteChatColor("You MUST provide a description for the waypoint", CONCOLOR_RED);
			return;
		}

		sprintf_s(szData, "%3.6f %3.6f %3.6f:%s", pChar->Y, pChar->X, pChar->Z, szDesc);
		WritePrivateProfileString(Zone->ShortName, szName, szData, WaypointsINI);

		sprintf_s(szMsg, "Waypoint \'%s\' added to %s.", szName, WaypointsINI);
		WriteChatColor(szMsg, COLOR_LIGHTGREY);
	}
	else if (!_stricmp(szCommand, "del")) {
		GetArg(szName, szLine, 2);

		if (szName[0] == 0) {
			WriteChatColor("Usage: /wp del <name>", CONCOLOR_RED);
			return;
		}

		WritePrivateProfileString(Zone->ShortName, szName, NULL, WaypointsINI);

		sprintf_s(szMsg, "Waypoint \'%s\' deleted.", szName);
		WriteChatColor(szMsg, COLOR_LIGHTGREY);
	}
	else if (!_stricmp(szCommand, "list")) {
		WriteChatColor("Waypoints List:");
		GetPrivateProfileSection(Zone->ShortName, WaypointList, MAX_STRING * 10, WaypointsINI);

		while (*pWaypointList) {
			strcpy_s(szBuffer, pWaypointList);
			GetArg(szKey, szBuffer, 1, 0, 0, 0, '=');
			GetArg(szValue, pWaypointList, 2, 0, 0, 0, '=');
			sprintf_s(szMsg, "%s = %s", szKey, szValue);
			WriteChatColor(szMsg, COLOR_LIGHTGREY);
			pWaypointList += strlen(pWaypointList) + 1;
		}
	}
	else {
		WriteChatColor("Usage: /wp add <name> <description>", CONCOLOR_RED);
		WriteChatColor("       /wp del <name>", CONCOLOR_RED);
		WriteChatColor("       /wp list", CONCOLOR_RED);
	}
}

// Function to write a float value to a specific memory address
void WriteFloatToMemory(DWORD_PTR address, float value)
{
	DWORD oldProtect;
	VirtualProtect((LPVOID)address, sizeof(float), PAGE_EXECUTE_READWRITE, &oldProtect);
	*(float*)address = value;
	VirtualProtect((LPVOID)address, sizeof(float), oldProtect, &oldProtect);
}
VOID DoWarp(float y, float x, float z)
{
	PZONEINFO Zone = (PZONEINFO)pZoneInfo;
	float SafeY = Zone->SafeYLoc;
	float SafeX = Zone->SafeXLoc;
	float SafeZ = Zone->SafeZLoc;

	Zone->SafeYLoc = y;
	Zone->SafeXLoc = x;
	Zone->SafeZLoc = z;
	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_Y, y);
	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_X, x);
	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_Z, z);

	CHAR szMsg[MAX_STRING] = { 0 };
	sprintf_s(szMsg, "Warping to: Y:%3.2f, X:%3.2f, Z:%3.2f.", Zone->SafeYLoc, Zone->SafeXLoc, Zone->SafeZLoc);
	WriteChatColor(szMsg, COLOR_PURPLE);

	DWORD MLPTSC = CDisplay__MoveLocalPlayerToSafeCoords;
	__asm call dword ptr[MLPTSC];

	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_Y, SafeY);
	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_X, SafeX);
	WriteFloatToMemory(BASE_ADDRESS + ADDRESS_SAFE_Z, SafeZ);
	Zone->SafeYLoc = SafeY;
	Zone->SafeXLoc = SafeX;
	Zone->SafeZLoc = SafeZ;
}

// Function to convert DWORD to hexadecimal string
std::string DWORDToHexString(DWORD value, INT maxLength) {
	std::stringstream stream;
	stream << "0x" << std::uppercase << std::setfill('0') << std::setw(maxLength) << std::hex << value;
	return stream.str();
}

DWORD_PTR GetModuleBaseAddress(DWORD dwProcID, LPCSTR moduleName) {
	DWORD_PTR dwBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 ModuleEntry32 = { sizeof(ModuleEntry32) };
		if (Module32First(hSnapshot, &ModuleEntry32)) {
			do {
				if (!_stricmp(ModuleEntry32.szModule, moduleName)) {
					dwBaseAddress = reinterpret_cast<DWORD_PTR>(ModuleEntry32.modBaseAddr);
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));
		}
		CloseHandle(hSnapshot);
	}
	return dwBaseAddress;
}

VOID AoBScan()
{
	const char* moduleName = "eqgame.exe";
	DWORD_PTR baseAddress = GetModuleBaseAddress(GetCurrentProcessId(), moduleName);
	std::string message3 = "[MQ2RWarp]BaseAddress: " + DWORDToHexString(baseAddress, 6);
	WriteChatColor(message3.c_str(), CONCOLOR_RED);
	BASE_ADDRESS = baseAddress;

	// Pattern and mask for MoveLocalPlayerToSafeCoords
	char* patternMLPTSC = "\xD9\x05\x00\x00\x00\x00\xA1\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD9\x58\x64\xD9\xC9\xD9\x58\x68\xD9\x58\x6C\x8B\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x6A\x00\x6A\x00\x6A\x03\xE8\x00\x00\x00\x00\xD9\xEE\xA1\x00\x00\x00\x00\xD9\x50\x70\xD9\x50\x74\x6A\x00\xD9\x50\x78\xA1\x00\x00\x00\x00\xD9\x90\x8C\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xD9\x91\x88\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xD9\x5A\x7C\xA1\x00\x00\x00\x00\xC7\x40\x24\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xC7\x81\xD4\x02\x00\x00\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x40\x8B\x50\x08\x8B\x4A\x04\x8B\x54\x01\x08\x8D\x4C\x01\x08\x8B\x42\x58\xFF\xD0\xD9\x05\x00\x00\x00\x00\xA1\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\x8B\x48\x08\xD9\x05\x00\x00\x00\x00\x8B\x51\x04\xD9\x5C\x02\x34\x8D\x44\x02\x08\xD9\xC9\xD9\x58\x30\xD9\x58\x34\xD9\x05\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xD8\x05\x00\x00\x00\x00\x6A\x01\x83\xEC\x0C\xD9\x5C\x24\x08\xD9\x05\x00\x00\x00\x00\xD9\x5C\x24\x04\xD9\x05\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xFF\x05\x00\x00\x00\x00\xD9\xC0\xD9\x05\x00\x00\x00\x00\xDA\xE9\xDF\xE0\xF6\xC4\x44\x7B\x0A\xA1\x00\x00\x00\x00\xD9\x58\x28\xEB\x02\xDD\xD8\x8B\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x85\xC9\x0F\x84\x00\x00\x00\x00\x3B\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0\x75\x13\x8B\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x85\xC0\x0F\x84\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xA1\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\x6A\x01\xD9\x05\x00\x00\x00\x00\x83\xEC\x0C\xD9\x58\x64\xD9\xC9\xD9\x58\x68\xD9\x58\x6C\x8B\x00\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD8\x05\x00\x00\x00\x00\xD9\x5C\x24\x08\xD9\x05\x00\x00\x00\x00\xD9\x5C\x24\x04\xD9\x05\x00\x00\x00\x00\xD9\x1C\x24\xE8\x00\x00\x00\x00\xD9\xC0\xD9\x05\x00\x00\x00\x00\xDA\xE9\xDF\xE0\xF6\xC4\x44\x7B\x14\x8B\x00\x00\x00\x00\x00\xD9\x59\x28\x8B\x00\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\xDD\xD8\xE9\x00\x00\x00\x00\xC3";
	char* maskMLPTSC = "xx????x????xx????xx????xxxxxxxxxxxx?????x????x?????xxxxxxx????xxx????xxxxxxxxxxxx????xxxxxxx?????xxxxxxx?????xxxx????xxxxxxxx?????x????x?????xxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxx????x????xx????xxxxx????xxxxxxxxxxxxxxxxxxxxx????x?????xx????xxxxxxxxxxx????xxxxxx????xxxx????xx????xxxx????xxxxxxxxxx????xxxxxxxx?????x????x?????xxxx????x?????xx????x????xxxxx?????x????xxxx????xx????x????xx????xxxx????xxxxxxxxxxxxxxx?????xx????xx????xxxxxx????xxxxxx????xxxx????xxxx????xxxxxxxxxx?????xxxx?????x????x?????xxx????x";

	// Pattern and mask for DoTheZone
	const char* patternDoTheZone = "\xA1\x00\x00\x00\x00\x50\xE8\x00\x00\x00\x00\xC3\xCC\xCC\xCC\xCC\x81\xEC\x1C\x08\x00\x00\x53\x8B\x9C\x24\x24\x08\x00\x00\x84\xDB\x74\x4D\x80\xB9\x80\x2D\x00\x00\x00\x74\x3A\x8D\x44\x24\x04\x50\xC7\x44\x24\x08\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x8B\x11\x8B\x92\xD0\x00\x00\x00\x6A\x01\x8D\x44\x24\x08\x50\xFF\xD2\x8B\x00\x00\x00\x00\x00\x8B\x01\x8B\x90\xD4\x00\x00\x00\x53\xFF\xD2\x5B\x81\xC4\x1C\x08\x00\x00\xC2\x04\x00";
	const char* maskDoTheZone = "x????xx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????x?????xxxxxxxxxxxxxxxxxx?????xxxxxxxxxxxxxxxxxxxxx";

	SignatureScanner SigScanner;
	if (SigScanner.GetProcess("eqgame.exe"))
	{
		module mod = SigScanner.GetModule("eqgame.exe");
		// scanning for the address of the variable:
		DWORD PlayerStructBase = SigScanner.FindSignature(mod.dwBase, mod.dwSize, patternMLPTSC, maskMLPTSC);
		CDisplay__MoveLocalPlayerToSafeCoords = PlayerStructBase;
		std::string message1 = "[MQ2RWarp]CDisplay__MoveLocalPlayerToSafeCoords: " + DWORDToHexString(PlayerStructBase, 6);
		WriteChatColor(message1.c_str(), CONCOLOR_RED);

		DWORD PlayerStructBase2 = SigScanner.FindSignature(mod.dwBase, mod.dwSize, patternDoTheZone, maskDoTheZone);
		LocalCEverQuest__DoTheZone = PlayerStructBase2;
		std::string message2 = "[MQ2RWarp]LocalCEverQuest__DoTheZone: " + DWORDToHexString(PlayerStructBase2, 6);
		WriteChatColor(message2.c_str(), CONCOLOR_RED);
		getchar();
	}
}

VOID ShowOffsetS()
{
	std::string message1 = "[MQ2RWarp]CDisplay__MoveLocalPlayerToSafeCoords: " + DWORDToHexString(CDisplay__MoveLocalPlayerToSafeCoords, 6);
	WriteChatColor(message1.c_str(), CONCOLOR_RED);
	std::string message2 = "[MQ2RWarp]LocalCEverQuest__DoTheZone: " + DWORDToHexString(LocalCEverQuest__DoTheZone, 6);
	WriteChatColor(message2.c_str(), CONCOLOR_RED);
}

VOID DoShowOffsets(PSPAWNINFO pChar, PCHAR szLine)
{
	ShowOffsetS();
}

VOID DoAoBScan(PSPAWNINFO pChar, PCHAR szLine)
{
	WriteChatColor("[MQ2RWarp]Starting AoB scan...", CONCOLOR_GREEN);
	AoBScan();
	WriteChatColor("[MQ2RWarp]AoB scan completed.", CONCOLOR_GREEN);
}

VOID GateBind(PSPAWNINFO pChar, PCHAR szLine)
{
	WriteChatColor("Gating...", CONCOLOR_RED);
	//pChar->Type = SPAWN_CORPSE;
	DWORD MLPTSC = CDisplay__MoveLocalPlayerToSafeCoords;
	__asm call dword ptr[MLPTSC];
}

VOID ZoneShift(PSPAWNINFO pChar, PCHAR szLine)
{
	CHAR szMsg[MAX_STRING] = { 0 };
	DWORD ZoneToGoTo = GetZoneID(szLine);

	if (ZoneToGoTo == -1) {
		WriteChatColor("Wrong Zone.ShortName, aborting!!", CONCOLOR_RED);
		return;
	}

	sprintf_s(szMsg, "Going to zone %s, id %d", szLine, ZoneToGoTo);
	WriteChatColor(szMsg, USERCOLOR_DEFAULT);

	PcProfile* pChar2 = GetPcProfile();
	pChar2->BoundLocations[0].ZoneBoundID = ZoneToGoTo;
	pChar->Type = SPAWN_CORPSE;
}

VOID doFade(PSPAWNINFO pChar, PCHAR szLine)
{
	PZONEINFO Zone = (PZONEINFO)pZoneInfo;
	int nZoneID = GetZoneID(Zone->ShortName);

	PcProfile* pChar2 = GetPcProfile();
	pChar2->BoundLocations[0].ZoneBoundID = nZoneID;
	pChar2->BoundLocations[0].ZoneBoundY = 0;
	pChar2->BoundLocations[0].ZoneBoundX = 0;
	pChar2->BoundLocations[0].ZoneBoundZ = 0;

	WriteChatColor("Fading Memories.", COLOR_PURPLE);
	pChar->Type = SPAWN_CORPSE;
}

PLUGIN_API VOID InitializePlugin(VOID)
{
	DebugSpewAlways("Initializing MQ2RWarp");
	AoBScan();
	AddCommand("/warp", Warp);
	AddCommand("/zwarp", zWarp);
	AddCommand("/loc", ExactLocation);
	AddCommand("/gate", GateBind);
	AddCommand("/zome", ZoneShift);
	AddCommand("/zone", ZoneShift);
	AddCommand("/fade", doFade);
	AddCommand("/aobscan", DoAoBScan);
	AddCommand("/warpoffsets", DoShowOffsets);
	AddCommand("/wp", waypoint);
}

PLUGIN_API VOID ShutdownPlugin(VOID)
{
	DebugSpewAlways("Shutting down MQ2RWarp");

	RemoveCommand("/warp");
	RemoveCommand("/zwarp");
	RemoveCommand("/loc");
	RemoveCommand("/gate");
	RemoveCommand("/zome");
	RemoveCommand("/zone");
	RemoveCommand("/fade");
	RemoveCommand("/aobscan");
	RemoveCommand("/warpoffsets");
	RemoveCommand("/wp");
}
