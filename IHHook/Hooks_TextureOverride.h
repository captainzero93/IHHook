#pragma once
#include "lua.h"
#include <cstdint>

namespace IHHook {
    namespace Hooks_TextureOverride {
        int CreateLibs(lua_State* L);
        bool HasRegistrations();
        void NotifyPath(uint64_t pathCode);

        // FoxBlockLoad uses a flagged/packed form of PathCode64. This associates
        // a fox::Block instance with any registered PFTXS container it starts loading.
        void NotifyBlockLoad(void* block, const uint64_t* pathCodes, uint32_t count);

        // Enter a per-thread Fox block Load/Process scope. Returns true when a
        // tracking frame was pushed and must later be paired with LeaveBlockProcess().
        // For target blocks the frame contains the registered fox::Block pointer;
        // for nested non-target blocks it contains nullptr to prevent false attribution.
        bool EnterBlockProcess(void* block, void* processBlockMemory);
        void LeaveBlockProcess();

        // BlockMemoryAllocTail can occur while a target FoxBlockLoad or Process is active.
        // The per-thread scope is the primary association; memBlock identity is only
        // retained as a secondary diagnostic.
        void NotifyBlockAllocation(void* blockMemory, void* allocation, uint64_t sizeInBytes,
            uint64_t alignment, uint32_t categoryTag);

        // Called after the original FoxBlockProcess. For registered target blocks this
        // inspects only recorded block allocations for a raw PFTX/TEXL container and
        // applies replacement entries in place.
        void ProcessBlock(void* block);
    }//namespace Hooks_TextureOverride
}//namespace IHHook
