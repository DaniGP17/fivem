#include <StdInc.h>
#include <ScriptEngine.h>
#include <Hooking.h>

#include "CfxRGBA.h"
#include "Hooking.Stubs.h"
#include "GamePrimitives.h"
#include "scrEngine.h"

enum ScriptImDrawType : uint32_t
{
	SCRIPT_IM_LINE = 0,
	SCRIPT_IM_POLY,
	SCRIPT_IM_BOX,
	SCRIPT_IM_BACKFACE_CULLING_OFF,
	SCRIPT_IM_BACKFACE_CULLING_ON,
};

struct ScriptImRequest
{
	rage::Vec3V m_first;
	rage::Vec3V m_second;
	rage::Vec3V m_third;
	uint32_t m_color;
	ScriptImDrawType m_type;
	char m_pad[8];
};

struct ScriptImPendingRequests
{
	ScriptImRequest* m_offset;
	uint16_t m_count;
	uint16_t m_size;
};

static constexpr int kMaxScriptImRequests = 1024;
static constexpr uint32_t kScriptImSharedDataBlockType = 20;
static std::vector<ScriptImRequest> g_scriptImRequests{};

static ScriptImPendingRequests* g_gameScriptImRequests;
static ScriptImRequest** g_scriptImFrameRequests;
static uint32_t* g_scriptImFrameCount;
static uintptr_t (*g_addSharedDataBlock)(uint32_t size, uint32_t type, bool multiBuffered);

static void AddScriptImRequest(const ScriptImRequest& request)
{
	if (g_scriptImRequests.size() >= kMaxScriptImRequests)
	{
		return;
	}

	g_scriptImRequests.push_back(request);
}

static void SnapshotScriptImRequests()
{
	const uint32_t gameCount = g_gameScriptImRequests->m_count;
	const uint32_t count = gameCount + static_cast<uint32_t>(g_scriptImRequests.size());

	*g_scriptImFrameCount = count;

	if (count == 0)
	{
		*g_scriptImFrameRequests = nullptr;
		return;
	}

	auto frameRequests = reinterpret_cast<ScriptImRequest*>(g_addSharedDataBlock(count * sizeof(ScriptImRequest), kScriptImSharedDataBlockType, false));

	std::copy_n(g_gameScriptImRequests->m_offset, gameCount, frameRequests);
	std::copy(g_scriptImRequests.begin(), g_scriptImRequests.end(), frameRequests + gameCount);

	*g_scriptImFrameRequests = frameRequests;

	g_gameScriptImRequests->m_count = 0;
	g_scriptImRequests.clear();
}

struct DrawOriginData
{
	rage::Vec3V m_pos;
	bool m_is2d; // +16
	char m_pad[15];
}; // 32

struct DrawOriginStore
{
	DrawOriginData m_items[32];
	uint32_t m_count;
	char pad_404[12];
};

static bool (*isGamePaused)();

static int* g_frameDrawIndex1;
static int* g_frameDrawIndex2;
static DrawOriginStore* g_drawOriginStore;
static uint32_t* g_scriptDrawOriginIndex;

struct WorldhorizonManager
{
	char m_unknown;
	char m_disableRendering;

	// etc...
};

static WorldhorizonManager* g_worldhorizonMgr;

CViewportGame** g_viewportGame;

static int* g_screenWidth;
static int* g_screenHeight;

static HookFunction hookFunction([]()
{
	static_assert(sizeof(ScriptImRequest) == 64);
	static_assert(sizeof(DrawOriginData) == 32);
	static_assert(sizeof(DrawOriginStore) == 1040);

	{
		g_viewportGame = hook::get_address<CViewportGame**>(hook::get_pattern("0F 2F F0 76 ? 4C 8B 35", 8));
		g_worldhorizonMgr = hook::get_address<WorldhorizonManager*>(hook::get_pattern("89 44 24 40 48 8D 0D ? ? ? ? 8B 84 24 90 00", 7));
	}

	{
		auto location = hook::get_pattern<char>("48 69 D0 10 04 00 00 48 8D 05 ? ? ? ? 48 03");

		g_frameDrawIndex1 = hook::get_address<int*>(location - 20);
		g_frameDrawIndex2 = hook::get_address<int*>(location - 7);
		g_drawOriginStore = hook::get_address<DrawOriginStore*>(location + 10);

		hook::set_call(&isGamePaused, location - 27);
	}

	{
		auto location = hook::get_pattern<char>("89 41 34 8B 05 ? ? ? ? 89 41 30 8A 05");
		g_scriptDrawOriginIndex = hook::get_address<uint32_t*>(location + 5);
	}

	{
		auto location = hook::get_pattern<char>("48 89 5C 24 ? 57 48 83 EC 20 0F B7 05 ? ? ? ? 33 FF");

		g_scriptImFrameCount = hook::get_address<uint32_t*>(location + 0x15);
		hook::set_call(&g_addSharedDataBlock, location + 0x2A);
		g_gameScriptImRequests = hook::get_address<ScriptImPendingRequests*>(location + 0x32);
		g_scriptImFrameRequests = hook::get_address<ScriptImRequest**>(location + 0x3F);

		hook::jump(location, SnapshotScriptImRequests);
	}

	{
		auto location = hook::get_pattern<char>("89 05 ? ? ? ? 89 0D ? ? ? ? F3 0F 5E");

		g_screenWidth = hook::get_address<int*>(location + 2);
		g_screenHeight = hook::get_address<int*>(location + 8);
	}

	fx::ScriptEngine::RegisterNativeHandler("SET_DRAW_ORIGIN", [](fx::ScriptContext& context)
	{
		auto drawIndex = *(isGamePaused() ? g_frameDrawIndex2 : g_frameDrawIndex1);

		auto& store = g_drawOriginStore[drawIndex];
		const auto index = store.m_count;

		if (index >= 32)
		{
			return;
		}

		DrawOriginData data;
		data.m_pos.x = context.GetArgument<float>(0);
		data.m_pos.y = context.GetArgument<float>(1);
		data.m_pos.z = context.GetArgument<float>(2);
		data.m_is2d = context.GetArgument<bool>(3);

		store.m_items[index] = data;
		store.m_count += 1;

		*g_scriptDrawOriginIndex = index;
	});

	fx::ScriptEngine::RegisterNativeHandler("CLEAR_DRAW_ORIGIN", [](fx::ScriptContext& context)
	{
		*g_scriptDrawOriginIndex = -1;
	});

	fx::ScriptEngine::RegisterNativeHandler("DRAW_LINE", [](fx::ScriptContext& context)
	{
		auto fromX = context.GetArgument<float>(0);
		auto fromY = context.GetArgument<float>(1);
		auto fromZ = context.GetArgument<float>(2);

		auto toX = context.GetArgument<float>(3);
		auto toY = context.GetArgument<float>(4);
		auto toZ = context.GetArgument<float>(5);

		auto red = context.GetArgument<uint8_t>(6);
		auto green = context.GetArgument<uint8_t>(7);
		auto blue = context.GetArgument<uint8_t>(8);
		auto alpha = context.GetArgument<uint8_t>(9);

		ScriptImRequest req;
		req.m_type = SCRIPT_IM_LINE;
		req.m_first = { fromX, fromY, fromZ };
		req.m_second = { toX, toY, toZ };
		req.m_color = CRGBA(red, green, blue, alpha).AsABGR();

		AddScriptImRequest(req);
	});

	fx::ScriptEngine::RegisterNativeHandler("DRAW_POLY", [](fx::ScriptContext& context)
	{
		auto firstX = context.GetArgument<float>(0);
		auto firstY = context.GetArgument<float>(1);
		auto firstZ = context.GetArgument<float>(2);

		auto secondX = context.GetArgument<float>(3);
		auto secondY = context.GetArgument<float>(4);
		auto secondZ = context.GetArgument<float>(5);

		auto thirdX = context.GetArgument<float>(6);
		auto thirdY = context.GetArgument<float>(7);
		auto thirdZ = context.GetArgument<float>(8);

		auto red = context.GetArgument<uint8_t>(9);
		auto green = context.GetArgument<uint8_t>(10);
		auto blue = context.GetArgument<uint8_t>(11);
		auto alpha = context.GetArgument<uint8_t>(12);

		ScriptImRequest req;
		req.m_type = SCRIPT_IM_POLY;
		req.m_first = { firstX, firstY, firstZ };
		req.m_second = { secondX, secondY, secondZ };
		req.m_third = { thirdX, thirdY, thirdZ };
		req.m_color = CRGBA(red, green, blue, alpha).AsABGR();

		AddScriptImRequest(req);
	});

	fx::ScriptEngine::RegisterNativeHandler("DRAW_BOX", [](fx::ScriptContext& context)
	{
		auto fromX = context.GetArgument<float>(0);
		auto fromY = context.GetArgument<float>(1);
		auto fromZ = context.GetArgument<float>(2);

		auto toX = context.GetArgument<float>(3);
		auto toY = context.GetArgument<float>(4);
		auto toZ = context.GetArgument<float>(5);

		auto red = context.GetArgument<uint8_t>(6);
		auto green = context.GetArgument<uint8_t>(7);
		auto blue = context.GetArgument<uint8_t>(8);
		auto alpha = context.GetArgument<uint8_t>(9);

		ScriptImRequest req;
		req.m_type = SCRIPT_IM_BOX;
		req.m_first = { fromX, fromY, fromZ };
		req.m_second = { toX, toY, toZ };
		req.m_color = CRGBA(red, green, blue, alpha).AsABGR();

		AddScriptImRequest(req);
	});

	fx::ScriptEngine::RegisterNativeHandler("SET_BACKFACECULLING", [](fx::ScriptContext& context)
	{
		auto flag = context.GetArgument<bool>(0);

		ScriptImRequest req;
		req.m_type = flag ? SCRIPT_IM_BACKFACE_CULLING_ON : SCRIPT_IM_BACKFACE_CULLING_OFF;

		AddScriptImRequest(req);
	});

	fx::ScriptEngine::RegisterNativeHandler("DISABLE_WORLDHORIZON_RENDERING", [](fx::ScriptContext& context)
	{
		auto flag = context.GetArgument<bool>(0);

		if (g_worldhorizonMgr)
		{
			g_worldhorizonMgr->m_disableRendering = flag;
		}
	});

	fx::ScriptEngine::RegisterNativeHandler("GET_WORLD_COORD_FROM_SCREEN_COORD", [](fx::ScriptContext& context)
	{
		float screenX = context.GetArgument<float>(0);
		float screenY = context.GetArgument<float>(1);

		using namespace DirectX;
		rage::Vec3V start = Unproject((*g_viewportGame)->viewport, rage::Vec3V{ screenX, screenY, 0.0f });
		rage::Vec3V end = Unproject((*g_viewportGame)->viewport, rage::Vec3V{ screenX, screenY, 1.0f });

		auto startVector = XMLoadFloat3((XMFLOAT3*)&start);
		auto endVector = XMLoadFloat3((XMFLOAT3*)&end);
		auto normalVector = XMVector3Normalize(XMVectorSubtract(endVector, startVector));

		scrVector* worldOut = context.GetArgument<scrVector*>(2);
		scrVector* normalOut = context.GetArgument<scrVector*>(3);

		worldOut->x = start.x;
		worldOut->y = start.y;
		worldOut->z = start.z;

		normalOut->x = XMVectorGetX(normalVector);
		normalOut->y = XMVectorGetY(normalVector);
		normalOut->z = XMVectorGetZ(normalVector);
	});

	fx::ScriptEngine::RegisterNativeHandler("GET_CURRENT_SCREEN_RESOLUTION", [](fx::ScriptContext& context)
	{
		int width = 0;
		int height = 0;

		if (g_screenWidth && g_screenHeight)
		{
			width = *g_screenWidth;
			height = *g_screenHeight;
		}

		*context.GetArgument<int*>(0) = width;
		*context.GetArgument<int*>(1) = height;
	});

	fx::ScriptEngine::RegisterNativeHandler("GET_ASPECT_RATIO", [](fx::ScriptContext& context)
	{
		float aspectRatio = 0.0f;

		if (g_screenWidth && g_screenHeight && *g_screenWidth && *g_screenHeight )
		{
			int width = *g_screenWidth;
			int height = *g_screenHeight;
			aspectRatio = static_cast<float>(width) / static_cast<float>(height);
		}

		context.SetResult<float>(aspectRatio);
	});
});
