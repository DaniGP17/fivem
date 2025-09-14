#include "StdInc.h"

#include "Hooking.h"
#include "Hooking.Stubs.h"

LPCRITICAL_SECTION g_lockCharClothRefList = nullptr;

static void (*g_origAddCharClothReference)(void* self, void* clothVarData);
static void AddCharClothReference(void* self, void* clothVarData)
{
	EnterCriticalSection(g_lockCharClothRefList);
	g_origAddCharClothReference(self, clothVarData);
	LeaveCriticalSection(g_lockCharClothRefList);
}

static HookFunction hookFunction([]
{
	g_lockCharClothRefList = hook::get_address<LPCRITICAL_SECTION>(hook::get_pattern("48 8D 0D ? ? ? ? 48 8B FA E8 ? ? ? ? 0F B7 83", 0x3));
	g_origAddCharClothReference = hook::trampoline(hook::get_call(hook::get_pattern("E8 ? ? ? ? FF C7 49 83 C4 ? 49 83 C7 ? 83 FF ? 0F 8C")), AddCharClothReference);
});