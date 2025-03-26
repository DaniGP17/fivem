#include "StdInc.h"
#include <Hooking.h>
#include <jitasm.h>
#include <mutex>

#include "Hooking.Stubs.h"

struct PatternPair;

enum class eSceneGraphPool : size_t
{
	FW_ENTITY_CONTAINER = 0,
	FW_FIXED_ENTITY_CONTAINER = 1,
	FW_SO_A_ENTITY_CONTAINER = 2,
	FW_EXTERIOR_SCENE_GRAPH_NODE = 3,
	FW_STREAMED_SCENE_GRAPH_NODE = 4,
	FW_INTERIOR_SCENE_GRAPH_NODE = 5,
	FW_ROOM_SCENE_GRAPH_NODE = 6,
	FW_PORTAL_SCENE_GRAPH_NODE = 7,
	COUNT
};

struct SceneGraphPoolData
{
	int classSize;
	int poolSize;
};

constexpr size_t POOL_COUNT = static_cast<size_t>(eSceneGraphPool::COUNT);
constexpr SceneGraphPoolData pools[POOL_COUNT] = {
	{48, 800},  // FW_ENTITY_CONTAINER
	{48, 2},    // FW_FIXED_ENTITY_CONTAINER(Max pool size is 64)
	{40, 1000}, // FW_SO_A_ENTITY_CONTAINER(This pool size will apply to FW_STREAMED_SCENE_GRAPH_NODE)
	{80, 1},    // FW_EXTERIOR_SCENE_GRAPH_NODE(This pool size can't be changed, due to asm inc instruction)
	{64, 1000}, // FW_STREAMED_SCENE_GRAPH_NODE (This pool size is going to be overwritten by FW_SO_A_ENTITY_CONTAINER)
	{32, 150},  // FW_INTERIOR_SCENE_GRAPH_NODE
	{48, 256},  // FW_ROOM_SCENE_GRAPH_NODE
	{128, 800}  // FW_PORTAL_SCENE_GRAPH_NODE
};

constexpr int FW_ENTITY_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_ENTITY_CONTAINER)].poolSize;
constexpr int FW_FIXED_ENTITY_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_FIXED_ENTITY_CONTAINER)].poolSize;
constexpr int FW_SO_A_ENTITY_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_SO_A_ENTITY_CONTAINER)].poolSize;
constexpr int FW_EXTERIOR_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_EXTERIOR_SCENE_GRAPH_NODE)].poolSize;
constexpr int FW_STREAMED_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_STREAMED_SCENE_GRAPH_NODE)].poolSize;
constexpr int FW_INTERIOR_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_INTERIOR_SCENE_GRAPH_NODE)].poolSize;
constexpr int FW_ROOM_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_ROOM_SCENE_GRAPH_NODE)].poolSize;
constexpr int FW_PORTAL_POOL_SIZE = pools[static_cast<size_t>(eSceneGraphPool::FW_PORTAL_SCENE_GRAPH_NODE)].poolSize;

constexpr int FIRST_STREAMED_SCENE_NODE_INDEX = FW_EXTERIOR_POOL_SIZE;
constexpr int FIRST_INTERIOR_SCENE_NODE_INDEX = FIRST_STREAMED_SCENE_NODE_INDEX + FW_STREAMED_POOL_SIZE;
constexpr int FIRST_ROOM_SCENE_NODE_INDEX = FIRST_INTERIOR_SCENE_NODE_INDEX + FW_INTERIOR_POOL_SIZE;
constexpr int FIRST_PORTAL_SCENE_NODE_INDEX = FIRST_ROOM_SCENE_NODE_INDEX + FW_ROOM_POOL_SIZE;
constexpr int MAX_SCENE_NODE_COUNT = FIRST_PORTAL_SCENE_NODE_INDEX + FW_PORTAL_POOL_SIZE;
constexpr int STORED_SCREEN_QUAD_COUNT = MAX_SCENE_NODE_COUNT - FIRST_ROOM_SCENE_NODE_INDEX + 1;

int CalculateTotalSize(bool storage) {
	int total = 0;
	for (size_t i = 0; i < POOL_COUNT; ++i) {
		const auto& pool = pools[i];
		total += storage ? (pool.poolSize * pool.classSize) : pool.poolSize;
	}
	return total;
}

struct PatternPair
{
	std::string_view pattern;
	int offset;
};

std::unique_ptr<uint8_t[]> skyPortalFlagArray = std::make_unique<uint8_t[]>((FW_PORTAL_POOL_SIZE + 7) / 8);

namespace rage
{
	struct fwFlags
	{
		uint8_t m_flags;
	};
	struct alignas(8) fwSceneGraphNode
	{
		rage::fwSceneGraphNode* m_next;
		rage::fwSceneGraphNode* m_firstChild;
		uint8_t m_type;
		rage::fwFlags m_flags;
		uint16_t m_index;
	};
	struct fwPortalSceneGraphNode : fwSceneGraphNode {};
	struct alignas(16) fwScanResultsSkyPortals
	{
		fwPortalSceneGraphNode* m_skyPortals[64];
		int m_skyPortalCount;
		uint8_t m_skyPortalFlags[50];
	};
}


static void AddSkyPortal(rage::fwScanResultsSkyPortals* self, rage::fwPortalSceneGraphNode* skyPortalNode)
{
	if(self->m_skyPortalCount >= 0 && self->m_skyPortalCount <= 63)
	{
		const uint16_t nodeIndex = skyPortalNode->m_index - FIRST_PORTAL_SCENE_NODE_INDEX;
		const uint8_t bitMask = 1 << (nodeIndex % 8);
		if((skyPortalFlagArray[nodeIndex/8] & bitMask) == 0)
		{
			skyPortalFlagArray[nodeIndex/8] |= bitMask;
			self->m_skyPortals[self->m_skyPortalCount++] = skyPortalNode;
		}
	}
}

static HookFunction hookFunction([]()
{
	assert(FW_FIXED_ENTITY_POOL_SIZE <= 64 && "The pool size of FW_FIXED_ENTITY_CONTAINER can't be greater than 64");
	auto initPoolsLocation = hook::get_pattern("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? BA ? ? ? ? B9"); // 48 8D B3 ? ? ? ? 48 8B FB
	auto assignStorageLocation = hook::get_pattern("48 8B C1 48 89 0D ? ? ? ? 48 81 C1");
	auto computeSceneNodeLocation = hook::get_pattern("4C 8B C1 0F B6 49 ? 85 C9");
	auto assignScratchBufferLocation = hook::get_pattern("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 48 89 91");
	auto clearVisDataLocation = hook::get_pattern("40 53 48 83 EC ? 48 8B D9 48 8B 89 ? ? ? ? 33 D2 41 B8");
	auto clearTraversalDataLocation = hook::get_pattern("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B7 81 ? ? ? ? 48 8B F9 48 8B 89");

	// Adjust the memory offsets of the allocated pools
	hook::put<uint32_t>((char*)initPoolsLocation + 88, FW_ENTITY_POOL_SIZE); // 800
	hook::put<uint32_t>((char*)initPoolsLocation + 98, FW_ENTITY_POOL_SIZE + FW_FIXED_ENTITY_POOL_SIZE); // 802
	hook::put<uint32_t>((char*)initPoolsLocation + 81, FW_SO_A_ENTITY_POOL_SIZE); // 1802
	hook::put<uint32_t>((char*)initPoolsLocation + 123, FW_INTERIOR_POOL_SIZE + FW_ROOM_POOL_SIZE); // 406

	const int poolStorageSize = CalculateTotalSize(true);
	const int poolFlagSize = CalculateTotalSize(false);

	// Change the size of poolStorage and poolFlags size
	hook::put<uint32_t>((char*)initPoolsLocation + 44, poolStorageSize);
	hook::put<uint32_t>((char*)initPoolsLocation + 34, poolStorageSize + poolFlagSize);

	// Change the pool size of each pool constructor
	hook::put<uint32_t>((char*)initPoolsLocation + 176, FW_ENTITY_POOL_SIZE);
	/*
	 * To apply the size in the constructor of FW_FIXED_ENTITY_CONTAINER we have to know that the value is being calculated based on an rdi calculation,
	 * above you can see the instruction "mov edi, 40h" and the argument is passed as "lea edx, [rdi-X]",
	 * we calculate this value X based on the pool size we want, by default the poolSize is 2, X is 3Eh because 64 - 2 = 62(3E)
	 */
	hook::put((char*)initPoolsLocation + 253, (uint8_t)(64 - FW_FIXED_ENTITY_POOL_SIZE));
	hook::put((char*)initPoolsLocation + 336, FW_SO_A_ENTITY_POOL_SIZE);
	// We skip the pool size of FW_EXTERIOR_SCENE_GRAPH_NODE because it can't be changed due to the limitations in the memory offsets when allocating the pools
	hook::put((char*)initPoolsLocation + 484, FW_STREAMED_POOL_SIZE);
	hook::put((char*)initPoolsLocation + 563, FW_INTERIOR_POOL_SIZE);
	hook::put((char*)initPoolsLocation + 646, FW_INTERIOR_POOL_SIZE);
	hook::put((char*)initPoolsLocation + 725, FW_PORTAL_POOL_SIZE);

	// Adjust offsets in AssignStorage function
	hook::put<uint32_t>((char*)assignStorageLocation + 13, FW_ENTITY_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_ENTITY_CONTAINER)].classSize); // 38400
	hook::put<uint8_t>((char*)assignStorageLocation + 27, static_cast<uint8_t>(FW_FIXED_ENTITY_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_FIXED_ENTITY_CONTAINER)].classSize)); // 96
	hook::put<uint32_t>((char*)assignStorageLocation + 45, FW_SO_A_ENTITY_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_SO_A_ENTITY_CONTAINER)].classSize); // 40000
	hook::put<uint8_t>((char*)assignStorageLocation + 59, static_cast<uint8_t>(FW_EXTERIOR_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_EXTERIOR_SCENE_GRAPH_NODE)].classSize)); // 80
	hook::put<uint32_t>((char*)assignStorageLocation + 70, FW_STREAMED_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_STREAMED_SCENE_GRAPH_NODE)].classSize); // 64000
	hook::put<uint32_t>((char*)assignStorageLocation + 84, FW_INTERIOR_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_INTERIOR_SCENE_GRAPH_NODE)].classSize); // 4800
	hook::put<uint32_t>((char*)assignStorageLocation + 98, FW_ROOM_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_ROOM_SCENE_GRAPH_NODE)].classSize); // 12288
	hook::put<uint32_t>((char*)assignStorageLocation + 113, FW_PORTAL_POOL_SIZE * pools[static_cast<size_t>(eSceneGraphPool::FW_PORTAL_SCENE_GRAPH_NODE)].classSize); // 102400

	// Adjust offsets in ComputeSceneNode function
	hook::put<uint32_t>((char*)computeSceneNodeLocation + 50, FW_EXTERIOR_POOL_SIZE + FW_STREAMED_POOL_SIZE + FW_INTERIOR_POOL_SIZE + FW_ROOM_POOL_SIZE); // 1407
	hook::put<uint32_t>((char*)computeSceneNodeLocation + 90, FW_EXTERIOR_POOL_SIZE + FW_STREAMED_POOL_SIZE + FW_INTERIOR_POOL_SIZE); // 1151
	hook::put<uint32_t>((char*)computeSceneNodeLocation + 113, FW_EXTERIOR_POOL_SIZE + FW_STREAMED_POOL_SIZE); // 1001

	// Adjust offsets in AssignScratchBuffer function
	std::initializer_list<int> assignScratchBufferSizes = {
		160, 177, 194, 211, 228
	};
	for(auto& offset : assignScratchBufferSizes)
	{
		// Combine two 16 bit values into a single 32 bit DWORD:
		// - Upper 16 bits (bitSize)
		// - Lower 16 bits (size)
		// Result: (bitSize << 16) | size
		hook::put<uint32_t>((char*)assignScratchBufferLocation + offset, (MAX_SCENE_NODE_COUNT << 16 ) | (MAX_SCENE_NODE_COUNT + 31) >> 5);
	}
	hook::put<uint32_t>((char*)assignScratchBufferLocation + 28, MAX_SCENE_NODE_COUNT * 4);
	hook::put<uint32_t>((char*)assignScratchBufferLocation + 54, STORED_SCREEN_QUAD_COUNT * 16);
	hook::put<uint32_t>((char*)clearVisDataLocation + 20, MAX_SCENE_NODE_COUNT * 4);

	// Adjust screen quad count
	hook::put<uint32_t>((char*)clearTraversalDataLocation + 236, STORED_SCREEN_QUAD_COUNT * 16);
	hook::put<uint32_t>((char*)clearTraversalDataLocation + 269, STORED_SCREEN_QUAD_COUNT * 16);

	// Change pool size of FIRST_ROOM_SCENE_NODE_INDEX
	std::initializer_list<PatternPair> roomSceneNodeIndexLocations = {
		{ "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 56 48 83 EC ? 4C 8B 91", 77 }, // AddVisibility
		{ "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 41 BB", 61 }, // ProcessEntityContainer
		{ "0F B7 42 ? 41 B8 ? ? ? ? 33 D2", 6 } // GetGbufScreenQuadPair
	};
	for(auto& entry : roomSceneNodeIndexLocations)
	{
		hook::put<uint32_t>(hook::get_pattern(entry.pattern, entry.offset),
			FW_EXTERIOR_POOL_SIZE +
			FW_STREAMED_POOL_SIZE +
			FW_INTERIOR_POOL_SIZE - 1);
	}

	// Patch AddSkyPortal
	auto addSkyPortalLocation = hook::get_pattern("83 B9 ? ? ? ? ? 4C 8B CA 4C 8B C1");
	hook::trampoline(addSkyPortalLocation, AddSkyPortal);

	// Patch SetIsSkyPortalVisInterior
	auto fwScanNodesRunPortalLocation = hook::get_pattern("48 8B 8B ? ? ? ? 33 D2 44 89 89");
	static struct : jitasm::Frontend
	{
		intptr_t location;
		void Init(intptr_t location)
		{
			this->location = location + 39;
		}
		
		void InternalMain() override
		{
			mov(rcx, qword_ptr[rbx+0xC38]);
			xor(edx, edx);
			mov(dword_ptr[rcx+0x378], r9d);
			mov(r8d, static_cast<size_t>((FW_PORTAL_POOL_SIZE + 7) / 8));
			mov(rcx, reinterpret_cast<uintptr_t>(skyPortalFlagArray.get()));
			mov(rax, (uintptr_t)memset);
			call(rax);
			xor(r9d, r9d);
			lea(r8d, dword_ptr[r9+1]);
			mov(rax, this->location);
			jmp(rax);
		}
	} fwScanNodesRunPortalStub;
	
	hook::nop(fwScanNodesRunPortalLocation, 39);
	fwScanNodesRunPortalStub.Init(reinterpret_cast<intptr_t>(fwScanNodesRunPortalLocation));
	hook::jump(fwScanNodesRunPortalLocation, fwScanNodesRunPortalStub.GetCode());
});
