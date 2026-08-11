// Runtime FTEX/PFTXS override support.
//
// Phase 1 registered generated Lua manifests and detected matching container loads.
// Phase 2 associates registered PFTXS loads with their QAR entries and can build a
// same-size encrypted shadow of the original QAR payload. ReadFile completion hooks
// overlay those shadow bytes into the game's archive reads, so Fox performs its normal
// QAR decrypt path and receives the modified PFTXS without changing the archive on disk.
//
// Important safety rule: this prototype never writes past the original PFTXS size.
// If the rebuilt container grows, it logs the required size and leaves game memory
// untouched. A later allocator-redirection path can cover that case.

#include "Hooks_TextureOverride.h"
#include "OS.h"
#include "spdlog/spdlog.h"
#include "lua/lauxlib.h"
#include "MinHook/MinHook.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace IHHook {
    namespace Hooks_TextureOverride {
        namespace {
            constexpr uint64_t FoxBlockPathMask = 0x0003FFFFFFFFFFFFull;
            constexpr uint32_t PftxMagic = 0x58544650u; // "PFTX"
            constexpr uint32_t TexlMagic = 0x4C584554u; // "TEXL"
            constexpr uint32_t FtexMagic = 0x58455446u; // "FTEX"
            constexpr size_t MaxPftxsSize = 128ull * 1024ull * 1024ull;
            constexpr size_t MaxAllocationScanBytes = 32ull * 1024ull * 1024ull;
            constexpr size_t MaxFallbackProbeBytes = 256ull * 1024ull;
            constexpr size_t BlockPointerProbeBytes = 0x200;
            constexpr uint64_t MaxProcessCalls = 512;

            // PFTXS I/O is asynchronous: FoxBlockLoad/Process can schedule work on
            // another thread. After a registered container request, briefly accept
            // allocator results from any thread, but keep the capture strictly bounded.
            constexpr uint64_t AsyncCaptureWindowMs = 5000;
            constexpr size_t AsyncMinAllocationSize = 64ull * 1024ull;
            constexpr size_t MaxAsyncAllocations = 256;
            constexpr size_t MaxAsyncCapturedBytes = 128ull * 1024ull * 1024ull;

            // Lower-level stream probe. The hook itself is cheap and scanning is only
            // enabled while a registered target PFTXS request is armed.
            constexpr size_t MaxRawReadCallsPerWindow = 1024;
            constexpr size_t MaxRawReadBytesPerWindow = 256ull * 1024ull * 1024ull;
            constexpr size_t MaxRawReadSingleScan = 32ull * 1024ull * 1024ull;
            constexpr size_t MaxRawHeaderLogs = 16;

            // MGSV QAR constants mirrored from the Fox_Parser/datfpk implementation.
            constexpr uint32_t QarXorMask1 = 0x41441043u;
            constexpr uint32_t QarXorMask2 = 0x11C22050u;
            constexpr uint32_t QarXorMask3 = 0xD05608C3u;
            constexpr uint32_t QarXorMask4 = 0x532C7319u;
            constexpr uint32_t QarEncryptionMagic1 = 0xA0F8EFE6u;
            constexpr uint32_t QarEncryptionMagic2 = 0xE3F8EFE6u;
            constexpr size_t QarHeaderSize = 32;
            constexpr size_t MaxQarFileCount = 500000;
            constexpr size_t MaxQarSectionBytes = 16ull * 1024ull * 1024ull;

            constexpr uint32_t QarXorTable[4] = {
                0x41441043u, 0x11C22050u, 0xD05608C3u, 0x532C7319u
            };

            constexpr uint32_t QarDecryptionTable[8] = {
                0xBB8ADEDBu, 0x65229958u, 0x08453206u, 0x88121302u,
                0x4C344955u, 0x2C02F10Cu, 0x4887F823u, 0xF3818583u
            };

            struct OverrideEntry {
                uint64_t pathHash = 0;
                std::string pathHashText;
                std::string vpath;
                std::string file;
                size_t declaredSize = 0;
                std::string absolutePath;
                std::vector<uint8_t> data;
            };

            struct ContainerEntry {
                uint64_t pathHash = 0;
                std::string pathHashText;
                std::string vpath;
            };

            struct Manifest {
                std::string name;
                std::string overrideRoot;
                std::vector<OverrideEntry> overrides;
                std::vector<ContainerEntry> containers;
            };

            struct RuntimeOverride {
                std::string owner;
                std::string vpath;
                std::string absolutePath;
                std::vector<uint8_t> data;
            };

            struct AllocationSpan {
                uint8_t* address = nullptr;
                size_t size = 0;
                uint64_t alignment = 0;
                uint32_t categoryTag = 0;
            };

            struct TargetBlockState {
                uint64_t canonicalContainerHash = 0;
                uint64_t rawLoadId = 0;
                std::string owners;
                uint64_t processCalls = 0;
                void* blockMemory = nullptr;
                size_t lastScannedAllocationCount = 0;
                std::vector<AllocationSpan> allocations;
                bool patched = false;
                bool growthFailureLogged = false;
                bool noBufferLogged = false;
                bool fallbackLogged = false;
            };

            struct ParsedEntry {
                uint64_t hash = 0;
                uint32_t offset = 0;
                uint32_t size = 0;
                const uint8_t* data = nullptr;
            };

            struct ParsedGroup {
                const uint8_t* base = nullptr;
                uint32_t originalSize = 0;
                uint32_t count = 0;
                std::vector<ParsedEntry> entries;
            };

            static std::mutex registryMutex;
            static std::vector<Manifest> manifests;
            static std::unordered_map<uint64_t, std::vector<std::string>> containerOwners;
            static std::unordered_map<uint64_t, std::vector<uint64_t>> containerLoadIndex;
            static std::unordered_map<uint64_t, std::shared_ptr<RuntimeOverride>> runtimeOverrides;
            static std::unordered_map<uint64_t, uint64_t> hitCounts;
            static std::unordered_map<void*, TargetBlockState> targetBlocks;
            // BlockMemory* -> fox::Block*. Kept as a secondary association.
            static std::unordered_map<void*, void*> blockMemoryOwners;

            // Bounded cross-thread capture armed by a target FoxBlockLoad request.
            static void* asyncCaptureTargetBlock = nullptr;
            static uint64_t asyncCaptureDeadlineMs = 0;
            static size_t asyncCaptureCount = 0;
            static size_t asyncCaptureBytes = 0;
            static size_t asyncCaptureLogged = 0;

            static size_t rawReadCallsScanned = 0;
            static size_t rawReadBytesScanned = 0;
            static size_t rawHeaderLogs = 0;

            struct QarLocation {
                std::wstring archivePath;
                std::string archiveDisplay;
                uint64_t pathHash = 0;
                uint64_t entryOffset = 0;
                uint64_t dataOffset = 0;
                uint32_t compressedSize = 0;
                uint32_t uncompressedSize = 0;
                uint32_t version = 0;
                std::array<uint8_t, 16> md5{};
            };

            struct QarShadow {
                std::wstring archivePath;
                std::string archiveDisplay;
                uint64_t pathHash = 0;
                uint64_t dataOffset = 0;
                size_t dataSize = 0;
                size_t pftxsOriginalSize = 0;
                size_t pftxsRebuiltSize = 0;
                size_t replacementCount = 0;
                std::vector<uint8_t> encryptedData;
            };

            static std::mutex qarMutex;
            static std::unordered_map<uint64_t, std::vector<QarLocation>> qarLocations;
            static std::unordered_map<std::wstring, std::vector<std::shared_ptr<QarShadow>>> qarShadowsByArchive;
            static std::unordered_set<uint64_t> qarPreparedHashes;
            static std::unordered_map<HANDLE, std::wstring> qarHandlePathCache;
            static std::atomic<bool> hasQarShadows{ false };

            struct PendingRead {
                HANDLE file = INVALID_HANDLE_VALUE;
                void* buffer = nullptr;
                DWORD requested = 0;
                uint64_t offset = 0;
                bool hasOffset = false;
            };

            static std::mutex pendingReadMutex;
            static std::unordered_map<LPOVERLAPPED, PendingRead> pendingReads;

            using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
            using GetOverlappedResultFn = BOOL(WINAPI*)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
            using GetQueuedCompletionStatusFn = BOOL(WINAPI*)(
                HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
            using GetQueuedCompletionStatusExFn = BOOL(WINAPI*)(
                HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);

            static ReadFileFn ReadFileOriginal = nullptr;
            static GetOverlappedResultFn GetOverlappedResultOriginal = nullptr;
            static GetQueuedCompletionStatusFn GetQueuedCompletionStatusOriginal = nullptr;
            static GetQueuedCompletionStatusExFn GetQueuedCompletionStatusExOriginal = nullptr;
            static std::atomic<bool> streamHooksInstalled{ false };
            thread_local bool insideStreamHook = false;

            static void EnsureStreamHooks();
            static void IndexRegisteredQarTargets();
            static void EnsureQarShadowPrepared(uint64_t pathHash);
            static bool OverlayQarShadow(
                HANDLE file, uint8_t* buffer, size_t bytesRead,
                uint64_t fileOffset, bool hasFileOffset, const char* source);
            static bool TryPatchRawReadBuffer(
                HANDLE file, uint8_t* buffer, size_t bytesRead,
                uint64_t fileOffset, bool hasFileOffset, const char* source);
            static bool BuildPatchedPftxs(
                const uint8_t* original, size_t originalAvailable,
                std::vector<uint8_t>& output, size_t& originalTotal,
                size_t& replacedCount, std::string& reason);

            // Each FoxBlockProcess call made after registration pushes one frame.
            // A target frame contains fox::Block*; a nested non-target frame is nullptr.
            thread_local std::vector<void*> processingTargetStack;

            static std::atomic<bool> hasRegistrations{ false };
            static std::atomic<bool> hasTargetBlocks{ false };

            static uint32_t ReadU32(const uint8_t* p) {
                uint32_t v;
                std::memcpy(&v, p, sizeof(v));
                return v;
            }

            static uint64_t ReadU64(const uint8_t* p) {
                uint64_t v;
                std::memcpy(&v, p, sizeof(v));
                return v;
            }

            static void WriteU32(uint8_t* p, uint32_t v) {
                std::memcpy(p, &v, sizeof(v));
            }

            static void WriteU64(uint8_t* p, uint64_t v) {
                std::memcpy(p, &v, sizeof(v));
            }

            static int AbsIndex(lua_State* L, int index) {
                return index < 0 ? lua_gettop(L) + index + 1 : index;
            }

            static std::string GetStringField(lua_State* L, int tableIndex, const char* key) {
                tableIndex = AbsIndex(L, tableIndex);
                lua_getfield(L, tableIndex, key);
                const char* value = lua_tostring(L, -1);
                std::string result = value == NULL ? "" : value;
                lua_pop(L, 1);
                return result;
            }

            static size_t GetSizeField(lua_State* L, int tableIndex, const char* key) {
                tableIndex = AbsIndex(L, tableIndex);
                lua_getfield(L, tableIndex, key);
                size_t result = 0;
                if (lua_isnumber(L, -1)) {
                    lua_Number value = lua_tonumber(L, -1);
                    if (value > 0)
                        result = static_cast<size_t>(value);
                }
                lua_pop(L, 1);
                return result;
            }

            static bool TryParseHash(const std::string& text, uint64_t& value) {
                if (text.empty())
                    return false;

                errno = 0;
                char* end = NULL;
                unsigned long long parsed = std::strtoull(text.c_str(), &end, 0);
                if (errno != 0 || end == text.c_str() || *end != '\0')
                    return false;

                value = static_cast<uint64_t>(parsed);
                return true;
            }

            static bool ReadHashField(lua_State* L, int tableIndex, uint64_t& value, std::string& text) {
                text = GetStringField(L, tableIndex, "pathHash");
                if (TryParseHash(text, value))
                    return true;

                text = GetStringField(L, tableIndex, "pathHashDecimal");
                return TryParseHash(text, value);
            }

            static bool ReadFileBytes(const std::filesystem::path& path, std::vector<uint8_t>& out) {
                std::ifstream f(path, std::ios::binary | std::ios::ate);
                if (!f)
                    return false;

                std::streamoff end = f.tellg();
                if (end < 0)
                    return false;

                out.resize(static_cast<size_t>(end));
                f.seekg(0, std::ios::beg);
                if (!out.empty())
                    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
                return f.good() || f.eof();
            }

            static void LoadOverrideData(Manifest& manifest) {
                const std::filesystem::path gameDir(OS::GetGameDirA());
                for (auto& entry : manifest.overrides) {
                    std::filesystem::path full = gameDir / std::filesystem::path(manifest.overrideRoot) / std::filesystem::path(entry.file);
                    full = full.lexically_normal();
                    entry.absolutePath = full.string();

                    if (!ReadFileBytes(full, entry.data)) {
                        spdlog::error("IHTextureOverride: could not read replacement '{}'", entry.absolutePath);
                        continue;
                    }

                    if (entry.declaredSize != 0 && entry.declaredSize != entry.data.size()) {
                        spdlog::warn("IHTextureOverride: replacement size changed for '{}' (manifest {}, disk {})",
                            entry.vpath, entry.declaredSize, entry.data.size());
                    }

                    spdlog::debug("IHTextureOverride: loaded replacement 0x{:016x}, {} bytes, '{}'",
                        entry.pathHash, entry.data.size(), entry.absolutePath);
                }
            }

            static void RebuildIndexesLocked() {
                containerOwners.clear();
                containerLoadIndex.clear();
                runtimeOverrides.clear();
                hitCounts.clear();
                targetBlocks.clear();
                blockMemoryOwners.clear();
                asyncCaptureTargetBlock = nullptr;
                asyncCaptureDeadlineMs = 0;
                asyncCaptureCount = 0;
                asyncCaptureBytes = 0;
                asyncCaptureLogged = 0;
                rawReadCallsScanned = 0;
                rawReadBytesScanned = 0;
                rawHeaderLogs = 0;

                {
                    std::lock_guard<std::mutex> qarLock(qarMutex);
                    qarLocations.clear();
                    qarShadowsByArchive.clear();
                    qarPreparedHashes.clear();
                    qarHandlePathCache.clear();
                    hasQarShadows.store(false, std::memory_order_release);
                }

                for (const auto& manifest : manifests) {
                    for (const auto& container : manifest.containers) {
                        auto& owners = containerOwners[container.pathHash];
                        if (std::find(owners.begin(), owners.end(), manifest.name) == owners.end())
                            owners.push_back(manifest.name);

                        auto& canonical = containerLoadIndex[container.pathHash & FoxBlockPathMask];
                        if (std::find(canonical.begin(), canonical.end(), container.pathHash) == canonical.end())
                            canonical.push_back(container.pathHash);
                    }

                    for (const auto& entry : manifest.overrides) {
                        if (entry.data.empty())
                            continue;

                        auto runtime = std::make_shared<RuntimeOverride>();
                        runtime->owner = manifest.name;
                        runtime->vpath = entry.vpath;
                        runtime->absolutePath = entry.absolutePath;
                        runtime->data = entry.data;
                        runtimeOverrides[entry.pathHash] = std::move(runtime); // latest registration wins
                    }
                }

                hasRegistrations.store(!containerOwners.empty() && !runtimeOverrides.empty(), std::memory_order_release);
                hasTargetBlocks.store(false, std::memory_order_release);
            }

            static std::string JoinOwners(const std::vector<std::string>& owners) {
                std::string text;
                for (size_t i = 0; i < owners.size(); ++i) {
                    if (i != 0)
                        text += ", ";
                    text += owners[i];
                }
                return text;
            }

            static int l_Register(lua_State* L) {
                luaL_checktype(L, 1, LUA_TTABLE);

                Manifest manifest;
                manifest.name = GetStringField(L, 1, "name");
                manifest.overrideRoot = GetStringField(L, 1, "overrideRoot");
                if (manifest.name.empty())
                    manifest.name = "UnnamedTextureOverride";

                lua_getfield(L, 1, "overrides");
                if (lua_istable(L, -1)) {
                    int listIndex = AbsIndex(L, -1);
                    size_t count = lua_objlen(L, listIndex);
                    for (size_t i = 1; i <= count; ++i) {
                        lua_rawgeti(L, listIndex, static_cast<int>(i));
                        if (lua_istable(L, -1)) {
                            OverrideEntry entry;
                            if (!ReadHashField(L, -1, entry.pathHash, entry.pathHashText)) {
                                lua_pop(L, 2);
                                return luaL_error(L, "IHTextureOverride.Register: invalid override pathHash at index %d", static_cast<int>(i));
                            }
                            entry.vpath = GetStringField(L, -1, "vpath");
                            entry.file = GetStringField(L, -1, "file");
                            entry.declaredSize = GetSizeField(L, -1, "size");
                            manifest.overrides.push_back(std::move(entry));
                        }
                        lua_pop(L, 1);
                    }
                }
                lua_pop(L, 1);

                lua_getfield(L, 1, "containers");
                if (lua_istable(L, -1)) {
                    int listIndex = AbsIndex(L, -1);
                    size_t count = lua_objlen(L, listIndex);
                    for (size_t i = 1; i <= count; ++i) {
                        lua_rawgeti(L, listIndex, static_cast<int>(i));
                        if (lua_istable(L, -1)) {
                            ContainerEntry entry;
                            if (!ReadHashField(L, -1, entry.pathHash, entry.pathHashText)) {
                                lua_pop(L, 2);
                                return luaL_error(L, "IHTextureOverride.Register: invalid container pathHash at index %d", static_cast<int>(i));
                            }
                            entry.vpath = GetStringField(L, -1, "vpath");
                            manifest.containers.push_back(std::move(entry));
                        }
                        lua_pop(L, 1);
                    }
                }
                lua_pop(L, 1);

                LoadOverrideData(manifest);

                const size_t overrideCount = manifest.overrides.size();
                const size_t containerCount = manifest.containers.size();
                const size_t loadedOverrideCount = static_cast<size_t>(std::count_if(
                    manifest.overrides.begin(), manifest.overrides.end(), [](const OverrideEntry& e) { return !e.data.empty(); }));
                const std::string manifestName = manifest.name;

                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    manifests.erase(
                        std::remove_if(manifests.begin(), manifests.end(),
                            [&](const Manifest& existing) { return existing.name == manifestName; }),
                        manifests.end());
                    manifests.push_back(std::move(manifest));
                    RebuildIndexesLocked();
                }

                spdlog::info("IHTextureOverride: registered '{}' ({} texture file(s), {} loaded, {} container(s))",
                    manifestName, overrideCount, loadedOverrideCount, containerCount);

                // Build a cheap metadata index of matching QAR entries. This scans
                // only QAR headers/section lists plus entry headers whose 40-bit section
                // signature can match one of our registered PFTXS hashes.
                IndexRegisteredQarTargets();

                // Generic OS read hooks are installed only when an override exists.
                // The QAR overlay itself remains dormant until a target shadow is built.
                EnsureStreamHooks();

                lua_pushboolean(L, loadedOverrideCount == overrideCount ? 1 : 0);
                return 1;
            }

            static int l_Clear(lua_State* L) {
                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    manifests.clear();
                    RebuildIndexesLocked();
                }
                spdlog::info("IHTextureOverride: registry cleared");
                return 0;
            }

            static int l_GetRegistrationCount(lua_State* L) {
                std::lock_guard<std::mutex> lock(registryMutex);
                lua_pushinteger(L, static_cast<lua_Integer>(manifests.size()));
                return 1;
            }

            static bool IsReadableProtection(DWORD protection) {
                if ((protection & PAGE_GUARD) != 0 || (protection & PAGE_NOACCESS) != 0)
                    return false;
                const DWORD p = protection & 0xff;
                return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
                    p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
            }

            static bool IsPlausiblePointer(uintptr_t p) {
                return p >= 0x10000ull && p < 0x0000800000000000ull;
            }

            static bool ParsePftxs(const uint8_t* base, size_t available, size_t& totalSize, std::vector<ParsedGroup>& groups, std::string& reason) {
                groups.clear();
                totalSize = 0;
                if (available < 32) {
                    reason = "header truncated";
                    return false;
                }
                if (ReadU32(base) != PftxMagic || ReadU32(base + 16) != TexlMagic) {
                    reason = "magic mismatch";
                    return false;
                }

                const uint32_t texlSize = ReadU32(base + 20);
                const uint32_t groupCount = ReadU32(base + 24);
                const uint64_t computedTotal = 16ull + texlSize;
                if (computedTotal < 32 || computedTotal > MaxPftxsSize || computedTotal > available) {
                    reason = "invalid TEXL size";
                    return false;
                }
                if (groupCount > 65535) {
                    reason = "implausible group count";
                    return false;
                }

                totalSize = static_cast<size_t>(computedTotal);
                size_t pos = 32;
                groups.reserve(groupCount);
                for (uint32_t g = 0; g < groupCount; ++g) {
                    if (pos + 32 > totalSize) {
                        reason = "group header truncated";
                        return false;
                    }
                    const uint8_t* groupBase = base + pos;
                    if (ReadU32(groupBase) != FtexMagic) {
                        reason = "group FTEX magic mismatch";
                        return false;
                    }

                    const uint32_t groupSize = ReadU32(groupBase + 4);
                    const uint32_t count = ReadU32(groupBase + 16);
                    if (groupSize < 32 || pos + groupSize > totalSize || count > 65535) {
                        reason = "invalid group size/count";
                        return false;
                    }
                    if (32ull + static_cast<uint64_t>(count) * 16ull > groupSize) {
                        reason = "entry table exceeds group";
                        return false;
                    }

                    ParsedGroup group;
                    group.base = groupBase;
                    group.originalSize = groupSize;
                    group.count = count;
                    group.entries.reserve(count);
                    for (uint32_t i = 0; i < count; ++i) {
                        const uint8_t* entryHdr = groupBase + 32 + static_cast<size_t>(i) * 16;
                        ParsedEntry entry;
                        entry.hash = ReadU64(entryHdr);
                        entry.offset = ReadU32(entryHdr + 8);
                        entry.size = ReadU32(entryHdr + 12);
                        if (entry.offset > groupSize || entry.size > groupSize ||
                            static_cast<uint64_t>(entry.offset) + entry.size > groupSize) {
                            reason = "entry data exceeds group";
                            return false;
                        }
                        entry.data = groupBase + entry.offset;
                        group.entries.push_back(entry);
                    }
                    groups.push_back(std::move(group));
                    pos += groupSize;
                }

                if (pos > totalSize) {
                    reason = "groups exceed TEXL";
                    return false;
                }
                return true;
            }

            static bool BuildPatchedPftxs(const uint8_t* original, size_t originalAvailable,
                std::vector<uint8_t>& output, size_t& originalTotal, size_t& replacedCount, std::string& reason) {
                std::vector<ParsedGroup> groups;
                if (!ParsePftxs(original, originalAvailable, originalTotal, groups, reason))
                    return false;

                std::unordered_map<uint64_t, std::shared_ptr<RuntimeOverride>> overrides;
                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    overrides = runtimeOverrides;
                }

                bool hasRelevantEntry = false;
                for (const auto& group : groups) {
                    for (const auto& entry : group.entries) {
                        if (overrides.find(entry.hash) != overrides.end()) {
                            hasRelevantEntry = true;
                            break;
                        }
                    }
                    if (hasRelevantEntry)
                        break;
                }
                if (!hasRelevantEntry) {
                    reason = "valid PFTX but no registered inner hashes";
                    return false;
                }

                output.clear();
                output.reserve(originalTotal);
                output.insert(output.end(), original, original + 32);
                replacedCount = 0;

                for (const auto& group : groups) {
                    const size_t outGroupPos = output.size();
                    const size_t headerAndEntries = 32ull + static_cast<size_t>(group.count) * 16ull;
                    output.insert(output.end(), group.base, group.base + headerAndEntries);

                    for (uint32_t i = 0; i < group.count; ++i) {
                        const ParsedEntry& entry = group.entries[i];
                        const uint8_t* data = entry.data;
                        size_t dataSize = entry.size;

                        auto replacement = overrides.find(entry.hash);
                        if (replacement != overrides.end()) {
                            data = replacement->second->data.data();
                            dataSize = replacement->second->data.size();
                            ++replacedCount;
                            spdlog::debug("IHTextureOverride: replacing inner 0x{:016x}, {} -> {} bytes ({})",
                                entry.hash, entry.size, dataSize, replacement->second->vpath);
                        }

                        const size_t newOffset = output.size() - outGroupPos;
                        if (newOffset > UINT32_MAX || dataSize > UINT32_MAX) {
                            reason = "rebuilt entry exceeds 32-bit PFTXS limits";
                            return false;
                        }

                        output.insert(output.end(), data, data + dataSize);
                        uint8_t* outEntry = output.data() + outGroupPos + 32 + static_cast<size_t>(i) * 16;
                        WriteU32(outEntry + 8, static_cast<uint32_t>(newOffset));
                        WriteU32(outEntry + 12, static_cast<uint32_t>(dataSize));
                    }

                    const size_t newGroupSize = output.size() - outGroupPos;
                    if (newGroupSize > UINT32_MAX) {
                        reason = "rebuilt group exceeds 32-bit PFTXS limits";
                        return false;
                    }
                    WriteU32(output.data() + outGroupPos + 4, static_cast<uint32_t>(newGroupSize));
                }

                if (replacedCount == 0) {
                    reason = "no entries replaced";
                    return false;
                }

                if (output.size() < 16 || output.size() - 16 > UINT32_MAX) {
                    reason = "rebuilt TEXL size exceeds 32-bit PFTXS limits";
                    return false;
                }
                WriteU32(output.data() + 20, static_cast<uint32_t>(output.size() - 16));
                return true;
            }

            static bool WritePatchedContainer(uint8_t* destination, size_t originalTotal,
                const std::vector<uint8_t>& rebuilt, std::string& reason) {
                if (rebuilt.size() > originalTotal) {
                    reason = "rebuilt container is larger than original memory span";
                    return false;
                }

                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(destination, &mbi, sizeof(mbi)) == 0) {
                    reason = "VirtualQuery failed for PFTXS destination";
                    return false;
                }

                const uint8_t* regionEnd = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (destination + originalTotal > regionEnd) {
                    reason = "PFTXS crosses memory protection region";
                    return false;
                }

                DWORD oldProtect = 0;
                const bool alreadyWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
                if (!alreadyWritable && !VirtualProtect(destination, originalTotal, PAGE_READWRITE, &oldProtect)) {
                    reason = "VirtualProtect(PAGE_READWRITE) failed";
                    return false;
                }

                std::memcpy(destination, rebuilt.data(), rebuilt.size());
                if (rebuilt.size() < originalTotal)
                    std::memset(destination + rebuilt.size(), 0, originalTotal - rebuilt.size());
                FlushInstructionCache(GetCurrentProcess(), destination, originalTotal);

                if (!alreadyWritable) {
                    DWORD ignored = 0;
                    VirtualProtect(destination, originalTotal, oldProtect, &ignored);
                }
                return true;
            }

            static bool TryPatchWindow(const uint8_t* begin, size_t length, const uint8_t* readableEnd, void* block,
                TargetBlockState& state, size_t& scannedBytes) {
                if (length < 32)
                    return false;

                scannedBytes += length;
                for (size_t i = 0; i + 32 <= length; ++i) {
                    if (begin[i] != 'P')
                        continue;
                    const uint8_t* candidate = begin + i;
                    if (ReadU32(candidate) != PftxMagic)
                        continue;
                    if (ReadU32(candidate + 16) != TexlMagic)
                        continue;

                    std::vector<uint8_t> rebuilt;
                    size_t originalTotal = 0;
                    size_t replacedCount = 0;
                    std::string reason;
                    const size_t readableAvailable = static_cast<size_t>(readableEnd - candidate);
                    const size_t parseAvailable = (std::min)(readableAvailable, MaxPftxsSize);
                    if (!BuildPatchedPftxs(candidate, parseAvailable, rebuilt, originalTotal, replacedCount, reason))
                        continue;

                    spdlog::info("IHTextureOverride: found PFTXS for block {} at {}, original {} bytes, rebuilt {} bytes, {} replacement(s)",
                        block, static_cast<const void*>(candidate), originalTotal, rebuilt.size(), replacedCount);

                    if (rebuilt.size() > originalTotal) {
                        if (!state.growthFailureLogged) {
                            spdlog::warn("IHTextureOverride: cannot patch 0x{:016x} in place: rebuilt PFTXS grows by {} bytes ({} -> {}). "
                                "Allocator redirection is required for this container.",
                                state.canonicalContainerHash, rebuilt.size() - originalTotal, originalTotal, rebuilt.size());
                            state.growthFailureLogged = true;
                        }
                        return false;
                    }

                    uint8_t* writable = const_cast<uint8_t*>(candidate);
                    if (!WritePatchedContainer(writable, originalTotal, rebuilt, reason)) {
                        spdlog::error("IHTextureOverride: PFTXS write failed for 0x{:016x}: {}",
                            state.canonicalContainerHash, reason);
                        return false;
                    }

                    spdlog::info("IHTextureOverride: MEMORY PATCHED container 0x{:016x} at {} ({} replacement(s), {} -> {} bytes)",
                        state.canonicalContainerHash, static_cast<void*>(writable), replacedCount, originalTotal, rebuilt.size());
                    return true;
                }
                return false;
            }



            static uint32_t QarRor32(uint32_t value, uint32_t rotation) {
                rotation &= 31u;
                if (rotation == 0)
                    return value;
                return (value >> rotation) | (value << (32u - rotation));
            }

            static uint64_t QarSectionSignature(uint64_t pathHash) {
                return ((pathHash & 0xffull) << 32) |
                    ((pathHash >> 32) & 0xffffffffull);
            }

            static std::wstring NormalizeArchivePath(std::wstring path) {
                if (path.rfind(L"\\\\?\\", 0) == 0)
                    path.erase(0, 4);

                std::replace(path.begin(), path.end(), L'/', L'\\');
                std::transform(path.begin(), path.end(), path.begin(),
                    [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
                return path;
            }

            static std::wstring AbsoluteNormalizedPath(
                const std::filesystem::path& path) {
                std::error_code ec;
                auto absolute = std::filesystem::absolute(path, ec);
                if (ec)
                    absolute = path;
                return NormalizeArchivePath(absolute.wstring());
            }

            static std::string NarrowPath(const std::wstring& path) {
                if (path.empty())
                    return {};

                int needed = WideCharToMultiByte(
                    CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()),
                    nullptr, 0, nullptr, nullptr);
                if (needed <= 0)
                    return "<path conversion failed>";

                std::string result(static_cast<size_t>(needed), '\0');
                WideCharToMultiByte(
                    CP_UTF8, 0, path.c_str(), static_cast<int>(path.size()),
                    result.data(), needed, nullptr, nullptr);
                return result;
            }

            static bool ReadExact(
                std::ifstream& file, uint64_t offset, void* destination,
                size_t size) {
                file.clear();
                file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
                if (!file)
                    return false;

                file.read(
                    reinterpret_cast<char*>(destination),
                    static_cast<std::streamsize>(size));
                return static_cast<size_t>(file.gcount()) == size;
            }

            static void QarDecodeMd5(
                const uint8_t encoded[16],
                std::array<uint8_t, 16>& decoded) {
                WriteU32(decoded.data() + 0, ReadU32(encoded + 0) ^ QarXorMask4);
                WriteU32(decoded.data() + 4, ReadU32(encoded + 4) ^ QarXorMask1);
                WriteU32(decoded.data() + 8, ReadU32(encoded + 8) ^ QarXorMask1);
                WriteU32(decoded.data() + 12, ReadU32(encoded + 12) ^ QarXorMask2);
            }

            // QAR Decrypt1 is XOR-based, so the same routine encrypts/decrypts.
            static void QarCrypt1(
                uint8_t* data, size_t size,
                const std::array<uint8_t, 16>& md5,
                uint64_t pathHash, uint32_t version,
                uint64_t position = 0) {

                if (data == nullptr || size == 0)
                    return;

                const uint32_t hashLow =
                    static_cast<uint32_t>(pathHash & 0xffffffffu);

                const size_t md5Offset =
                    static_cast<size_t>(hashLow % 2u) * 8u;

                const uint64_t seed = ReadU64(md5.data() + md5Offset);
                const uint32_t seedLow =
                    static_cast<uint32_t>(seed & 0xffffffffu);
                const uint32_t seedHigh =
                    static_cast<uint32_t>(seed >> 32);

                const size_t blocks = size / 8;
                for (size_t i = 0; i < blocks; ++i) {
                    const size_t off1 = i * 8;
                    const size_t off2 = off1 + 4;
                    const uint64_t abs = position + off1;

                    int index = 0;
                    if (version == 2) {
                        index = 2 * static_cast<int>(
                            (static_cast<uint64_t>(hashLow) +
                                seed + (abs / 11ull)) % 4ull);
                    }
                    else {
                        index = 2 * static_cast<int>(
                            (static_cast<uint64_t>(hashLow) +
                                (abs / 11ull)) % 4ull);
                    }

                    uint32_t u1 = ReadU32(data + off1) ^
                        QarDecryptionTable[index];
                    uint32_t u2 = ReadU32(data + off2) ^
                        QarDecryptionTable[index + 1];

                    if (version == 2) {
                        u1 ^= seedLow;
                        u2 ^= seedHigh;
                    }

                    WriteU32(data + off1, u1);
                    WriteU32(data + off2, u2);
                }

                const size_t rem = size % 8;
                for (size_t i = 0; i < rem; ++i) {
                    const size_t offset = blocks * 8 + i;
                    const size_t offsetBlock = offset - (offset % 8);
                    const uint64_t absBlock =
                        position + static_cast<uint64_t>(offsetBlock);

                    int index = 0;
                    if (version == 2) {
                        index = 2 * static_cast<int>(
                            (static_cast<uint64_t>(hashLow) +
                                seed + (absBlock / 11ull)) % 4ull);
                    }
                    else {
                        index = 2 * static_cast<int>(
                            (static_cast<uint64_t>(hashLow) +
                                (absBlock / 11ull)) % 4ull);
                    }

                    const int decIndex = static_cast<int>(offset % 8);
                    uint32_t xorMask = QarDecryptionTable[index + 1];
                    uint32_t seedMask = seedHigh;

                    if (decIndex < 4) {
                        xorMask = QarDecryptionTable[index];
                        seedMask = seedLow;
                    }

                    const int byteIndex = decIndex % 4;
                    uint8_t mask = static_cast<uint8_t>(
                        (xorMask >> (8 * byteIndex)) & 0xffu);

                    if (version == 2) {
                        mask ^= static_cast<uint8_t>(
                            (seedMask >> (8 * byteIndex)) & 0xffu);
                    }

                    data[offset] ^= mask;
                }
            }

            // QAR Decrypt2 is also XOR-based.
            static void QarCrypt2(
                uint8_t* data, size_t size, uint32_t key) {
                if (data == nullptr || size < 4)
                    return;

                const uint32_t k = key * 278u;
                uint32_t blockKey =
                    key | ((key ^ 25974u) << 16);

                size_t pos = 0;
                while (pos + 4 <= size) {
                    uint32_t value = ReadU32(data + pos) ^ blockKey;
                    WriteU32(data + pos, value);
                    blockKey = k + 48828125u * blockKey;
                    pos += 4;
                }
            }

            static bool QarDecryptSections(
                const std::vector<uint8_t>& blob,
                uint32_t fileCount, uint32_t version,
                std::vector<uint64_t>& sections) {

                if (blob.size() != static_cast<size_t>(fileCount) * 8ull)
                    return false;

                sections.resize(fileCount);

                if (version == 2) {
                    uint64_t xorValue = 0xA2C18EC3ull;

                    for (uint32_t i = 0; i < fileCount; ++i) {
                        const uint64_t off1 = static_cast<uint64_t>(i) * 8ull;
                        const uint64_t off2 = off1 + 4ull;

                        const int idx1 = static_cast<int>(
                            (xorValue + (off1 / 5ull)) % 4ull);
                        const int idx2 = static_cast<int>(
                            (xorValue + (off2 / 5ull)) % 4ull);

                        const uint32_t i1 =
                            ReadU32(blob.data() + off1) ^ QarXorTable[idx1];
                        const uint32_t i2 =
                            ReadU32(blob.data() + off2) ^ QarXorTable[idx2];

                        sections[i] =
                            (static_cast<uint64_t>(i2) << 32) | i1;

                        const uint32_t rotation = (i2 / 256u) % 19u;
                        xorValue ^= QarRor32(i1, rotation);
                    }

                    return true;
                }

                for (uint32_t i = 0; i < fileCount; ++i) {
                    const uint64_t off1 = static_cast<uint64_t>(i) * 8ull;
                    const uint64_t off2 = off1 + 4ull;

                    const int idx1 = static_cast<int>(
                        (static_cast<uint64_t>(i) + (off1 / 5ull)) % 4ull);
                    const int idx2 = static_cast<int>(
                        (static_cast<uint64_t>(i) + (off2 / 5ull)) % 4ull);

                    const uint32_t i1 =
                        ReadU32(blob.data() + off1) ^ QarXorTable[idx1];
                    const uint32_t i2 =
                        ReadU32(blob.data() + off2) ^ QarXorTable[idx2];

                    sections[i] =
                        (static_cast<uint64_t>(i2) << 32) | i1;
                }

                return true;
            }

            static bool ParseQarLocation(
                const std::filesystem::path& archive,
                std::ifstream& file,
                uint64_t fileSize,
                uint64_t sectionOffset,
                uint32_t version,
                uint64_t expectedHash,
                QarLocation& location) {

                if (sectionOffset + QarHeaderSize > fileSize)
                    return false;

                uint8_t entryHeader[QarHeaderSize]{};
                if (!ReadExact(file, sectionOffset, entryHeader, sizeof(entryHeader)))
                    return false;

                const uint32_t hashLow =
                    ReadU32(entryHeader + 0) ^ QarXorMask1;
                const uint32_t hashHigh =
                    ReadU32(entryHeader + 4) ^ QarXorMask1;

                const uint64_t pathHash =
                    (static_cast<uint64_t>(hashHigh) << 32) | hashLow;

                if (pathHash != expectedHash)
                    return false;

                const uint32_t compressed =
                    ReadU32(entryHeader + 8) ^ QarXorMask2;
                const uint32_t uncompressed =
                    ReadU32(entryHeader + 12) ^ QarXorMask3;

                const uint64_t stored =
                    (std::max)(
                        static_cast<uint64_t>(compressed),
                        static_cast<uint64_t>(uncompressed));

                if (stored < 32 || stored > MaxPftxsSize + 16ull ||
                    sectionOffset + QarHeaderSize + stored > fileSize)
                    return false;

                location.archivePath = AbsoluteNormalizedPath(archive);
                location.archiveDisplay = NarrowPath(location.archivePath);
                location.pathHash = pathHash;
                location.entryOffset = sectionOffset;
                location.dataOffset = sectionOffset + QarHeaderSize;
                location.compressedSize = compressed;
                location.uncompressedSize = uncompressed;
                location.version = version;
                QarDecodeMd5(entryHeader + 16, location.md5);

                return true;
            }

            static bool IsPotentialGameArchive(
                const std::filesystem::path& path) {
                auto ext = path.extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(),
                    [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
                return ext == L".dat" || ext == L".qar";
            }

            static void IndexRegisteredQarTargets() {
                std::unordered_set<uint64_t> targets;
                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    for (const auto& pair : containerOwners)
                        targets.insert(pair.first);
                }

                if (targets.empty())
                    return;

                std::unordered_map<uint64_t, std::vector<uint64_t>> signatures;
                for (uint64_t hash : targets)
                    signatures[QarSectionSignature(hash)].push_back(hash);

                std::unordered_map<uint64_t, std::vector<QarLocation>> foundLocations;
                size_t qarCount = 0;
                size_t candidateHeaders = 0;

                wchar_t exePath[MAX_PATH * 4]{};
                DWORD exeLength = GetModuleFileNameW(
                    nullptr, exePath,
                    static_cast<DWORD>(std::size(exePath)));

                std::filesystem::path gameRoot;
                if (exeLength != 0 && exeLength < std::size(exePath))
                    gameRoot = std::filesystem::path(exePath).parent_path();
                else
                    gameRoot = std::filesystem::current_path();

                std::error_code iteratorError;
                std::filesystem::recursive_directory_iterator iterator(
                    gameRoot,
                    std::filesystem::directory_options::skip_permission_denied,
                    iteratorError);

                const std::filesystem::recursive_directory_iterator end;

                for (; iterator != end; iterator.increment(iteratorError)) {
                    if (iteratorError) {
                        iteratorError.clear();
                        continue;
                    }

                    std::error_code typeError;
                    if (!iterator->is_regular_file(typeError) || typeError)
                        continue;

                    const auto archive = iterator->path();
                    if (!IsPotentialGameArchive(archive))
                        continue;

                    std::ifstream file(archive, std::ios::binary);
                    if (!file)
                        continue;

                    uint8_t header[QarHeaderSize]{};
                    file.read(
                        reinterpret_cast<char*>(header),
                        static_cast<std::streamsize>(sizeof(header)));

                    if (static_cast<size_t>(file.gcount()) != sizeof(header) ||
                        header[0] != 'S' || header[1] != 'Q' ||
                        header[2] != 'A' || header[3] != 'R')
                        continue;

                    ++qarCount;

                    const uint32_t flags =
                        ReadU32(header + 4) ^ QarXorMask1;
                    const uint32_t fileCount =
                        ReadU32(header + 8) ^ QarXorMask2;
                    const uint32_t version =
                        ReadU32(header + 24) ^ QarXorMask1;

                    if (fileCount == 0 ||
                        fileCount > MaxQarFileCount ||
                        static_cast<uint64_t>(fileCount) * 8ull >
                            MaxQarSectionBytes)
                        continue;

                    std::error_code sizeError;
                    const uint64_t fileSize =
                        std::filesystem::file_size(archive, sizeError);

                    if (sizeError || fileSize < QarHeaderSize)
                        continue;

                    std::vector<uint8_t> sectionBlob(
                        static_cast<size_t>(fileCount) * 8ull);

                    file.read(
                        reinterpret_cast<char*>(sectionBlob.data()),
                        static_cast<std::streamsize>(sectionBlob.size()));

                    if (static_cast<size_t>(file.gcount()) != sectionBlob.size())
                        continue;

                    std::vector<uint64_t> sections;
                    if (!QarDecryptSections(
                        sectionBlob, fileCount, version, sections))
                        continue;

                    const int shift =
                        (flags & 0x800u) != 0 ? 12 : 10;

                    for (uint64_t section : sections) {
                        const uint64_t signature =
                            section & 0xffffffffffull;

                        auto signatureIt = signatures.find(signature);
                        if (signatureIt == signatures.end())
                            continue;

                        ++candidateHeaders;

                        const uint64_t sectionBlock = section >> 40;
                        const uint64_t sectionOffset =
                            sectionBlock << shift;

                        for (uint64_t expectedHash :
                            signatureIt->second) {
                            QarLocation location;
                            if (ParseQarLocation(
                                archive, file, fileSize,
                                sectionOffset, version,
                                expectedHash, location)) {

                                auto& locations =
                                    foundLocations[expectedHash];

                                bool duplicate = false;
                                for (const auto& existing : locations) {
                                    if (existing.archivePath ==
                                            location.archivePath &&
                                        existing.dataOffset ==
                                            location.dataOffset) {
                                        duplicate = true;
                                        break;
                                    }
                                }

                                if (!duplicate)
                                    locations.push_back(
                                        std::move(location));
                            }
                        }
                    }
                }

                size_t locationCount = 0;
                size_t resolvedHashes = 0;
                for (const auto& pair : foundLocations) {
                    if (!pair.second.empty()) {
                        ++resolvedHashes;
                        locationCount += pair.second.size();
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    qarLocations = std::move(foundLocations);
                    qarShadowsByArchive.clear();
                    qarPreparedHashes.clear();
                    qarHandlePathCache.clear();
                    hasQarShadows.store(false, std::memory_order_release);
                }

                spdlog::info(
                    "IHTextureOverride: QAR index scanned {} archive(s), "
                    "{} candidate header(s); resolved {}/{} registered container hash(es) "
                    "to {} physical QAR entrie(s)",
                    qarCount, candidateHeaders,
                    resolvedHashes, targets.size(), locationCount);
            }

            static bool BuildQarShadow(
                const QarLocation& location,
                std::shared_ptr<QarShadow>& shadowOut) {

                if (location.compressedSize !=
                    location.uncompressedSize) {
                    spdlog::warn(
                        "IHTextureOverride: QAR target 0x{:016x} in '{}' is "
                        "outer-compressed ({} -> {}); shadow overlay currently "
                        "supports stored PFTXS entries only",
                        location.pathHash, location.archiveDisplay,
                        location.compressedSize,
                        location.uncompressedSize);
                    return false;
                }

                const size_t storedSize =
                    static_cast<size_t>((std::max)(
                        location.compressedSize,
                        location.uncompressedSize));

                std::ifstream file(
                    std::filesystem::path(location.archivePath),
                    std::ios::binary);

                if (!file)
                    return false;

                std::vector<uint8_t> mdata(storedSize);
                if (!ReadExact(
                    file, location.dataOffset,
                    mdata.data(), mdata.size()))
                    return false;

                // Remove QAR Decrypt1.
                QarCrypt1(
                    mdata.data(), mdata.size(),
                    location.md5, location.pathHash,
                    location.version, 0);

                size_t dataHeaderSize = 0;
                uint32_t dataKey = 0;

                if (mdata.size() >= 8) {
                    const uint32_t magic = ReadU32(mdata.data());
                    if (magic == QarEncryptionMagic1 ||
                        magic == QarEncryptionMagic2) {
                        dataHeaderSize =
                            magic == QarEncryptionMagic1 ? 8u : 16u;
                        dataKey = ReadU32(mdata.data() + 4);
                    }
                }

                if (dataHeaderSize > mdata.size())
                    return false;

                std::vector<uint8_t> plaintext(
                    mdata.begin() +
                        static_cast<std::ptrdiff_t>(dataHeaderSize),
                    mdata.end());

                if (dataHeaderSize != 0)
                    QarCrypt2(
                        plaintext.data(), plaintext.size(), dataKey);

                std::vector<uint8_t> rebuilt;
                size_t originalTotal = 0;
                size_t replacementCount = 0;
                std::string reason;

                if (!BuildPatchedPftxs(
                    plaintext.data(), plaintext.size(),
                    rebuilt, originalTotal,
                    replacementCount, reason)) {

                    spdlog::debug(
                        "IHTextureOverride: QAR target 0x{:016x} in '{}' "
                        "did not build a replacement: {}",
                        location.pathHash,
                        location.archiveDisplay, reason);
                    return false;
                }

                if (rebuilt.size() > plaintext.size()) {
                    spdlog::warn(
                        "IHTextureOverride: QAR shadow cannot fit "
                        "0x{:016x} in '{}': rebuilt PFTXS grows by {} bytes "
                        "({} -> {}, outer payload capacity {})",
                        location.pathHash, location.archiveDisplay,
                        rebuilt.size() - originalTotal,
                        originalTotal, rebuilt.size(),
                        plaintext.size());
                    return false;
                }

                // Preserve any bytes outside the PFTXS' declared original span.
                // Inside that span, zero trailing bytes when the rebuilt PFTXS shrinks.
                if (originalTotal > plaintext.size())
                    return false;

                std::copy(
                    rebuilt.begin(), rebuilt.end(),
                    plaintext.begin());

                if (rebuilt.size() < originalTotal) {
                    std::fill(
                        plaintext.begin() +
                            static_cast<std::ptrdiff_t>(rebuilt.size()),
                        plaintext.begin() +
                            static_cast<std::ptrdiff_t>(originalTotal),
                        0);
                }

                if (dataHeaderSize != 0)
                    QarCrypt2(
                        plaintext.data(), plaintext.size(), dataKey);

                std::copy(
                    plaintext.begin(), plaintext.end(),
                    mdata.begin() +
                        static_cast<std::ptrdiff_t>(dataHeaderSize));

                // Re-apply Decrypt1 using the ORIGINAL MD5 seed. We deliberately
                // do not change the on-disk/QAR entry header: Fox may have cached
                // it before the Lua manifest registers. Keeping its MD5 and sizes
                // unchanged makes our shadow compatible with that cached metadata.
                QarCrypt1(
                    mdata.data(), mdata.size(),
                    location.md5, location.pathHash,
                    location.version, 0);

                auto shadow = std::make_shared<QarShadow>();
                shadow->archivePath = location.archivePath;
                shadow->archiveDisplay = location.archiveDisplay;
                shadow->pathHash = location.pathHash;
                shadow->dataOffset = location.dataOffset;
                shadow->dataSize = mdata.size();
                shadow->pftxsOriginalSize = originalTotal;
                shadow->pftxsRebuiltSize = rebuilt.size();
                shadow->replacementCount = replacementCount;
                shadow->encryptedData = std::move(mdata);

                shadowOut = std::move(shadow);
                return true;
            }

            static void EnsureQarShadowPrepared(uint64_t pathHash) {
                std::vector<QarLocation> locations;

                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    if (qarPreparedHashes.find(pathHash) !=
                        qarPreparedHashes.end())
                        return;

                    qarPreparedHashes.insert(pathHash);

                    auto found = qarLocations.find(pathHash);
                    if (found != qarLocations.end())
                        locations = found->second;
                }

                if (locations.empty()) {
                    spdlog::warn(
                        "IHTextureOverride: no physical QAR location indexed for "
                        "container 0x{:016x}",
                        pathHash);
                    return;
                }

                // Our own std::ifstream work may ultimately call ReadFile. Bypass
                // the runtime hook on this thread while constructing shadow data.
                const bool previousInside = insideStreamHook;
                insideStreamHook = true;

                std::vector<std::shared_ptr<QarShadow>> built;

                for (const auto& location : locations) {
                    std::shared_ptr<QarShadow> shadow;
                    if (BuildQarShadow(location, shadow) &&
                        shadow != nullptr)
                        built.push_back(std::move(shadow));
                }

                insideStreamHook = previousInside;

                if (built.empty()) {
                    spdlog::warn(
                        "IHTextureOverride: indexed {} QAR location(s) for "
                        "0x{:016x}, but no same-size encrypted shadow could be built",
                        locations.size(), pathHash);
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    for (auto& shadow : built) {
                        qarShadowsByArchive[
                            shadow->archivePath].push_back(shadow);

                        spdlog::info(
                            "IHTextureOverride: QAR SHADOW READY "
                            "0x{:016x} in '{}' file+0x{:x}, {} bytes "
                            "({} replacement(s), PFTXS {} -> {})",
                            shadow->pathHash,
                            shadow->archiveDisplay,
                            shadow->dataOffset,
                            shadow->dataSize,
                            shadow->replacementCount,
                            shadow->pftxsOriginalSize,
                            shadow->pftxsRebuiltSize);
                    }

                    qarHandlePathCache.clear();
                    hasQarShadows.store(
                        !qarShadowsByArchive.empty(),
                        std::memory_order_release);
                }
            }

            static bool ResolveHandleArchivePath(
                HANDLE file, std::wstring& normalized) {
                if (file == nullptr || file == INVALID_HANDLE_VALUE)
                    return false;

                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    auto cached = qarHandlePathCache.find(file);
                    if (cached != qarHandlePathCache.end()) {
                        normalized = cached->second;
                        return !normalized.empty();
                    }
                }

                wchar_t path[2048]{};
                DWORD length = GetFinalPathNameByHandleW(
                    file, path,
                    static_cast<DWORD>(std::size(path)),
                    FILE_NAME_NORMALIZED);

                if (length == 0 || length >= std::size(path))
                    return false;

                normalized = NormalizeArchivePath(
                    std::wstring(path, length));

                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    qarHandlePathCache[file] = normalized;
                }
                return true;
            }

            static bool OverlayQarShadow(
                HANDLE file, uint8_t* buffer, size_t bytesRead,
                uint64_t fileOffset, bool hasFileOffset,
                const char* source) {

                if (!hasQarShadows.load(std::memory_order_acquire) ||
                    buffer == nullptr || bytesRead == 0 ||
                    !hasFileOffset)
                    return false;

                std::wstring archivePath;
                if (!ResolveHandleArchivePath(file, archivePath))
                    return false;

                std::vector<std::shared_ptr<QarShadow>> shadows;
                {
                    std::lock_guard<std::mutex> lock(qarMutex);
                    auto found = qarShadowsByArchive.find(archivePath);
                    if (found == qarShadowsByArchive.end())
                        return false;
                    shadows = found->second;
                }

                const uint64_t readStart = fileOffset;
                const uint64_t readEnd =
                    readStart + static_cast<uint64_t>(bytesRead);

                bool touched = false;

                for (const auto& shadow : shadows) {
                    if (shadow == nullptr ||
                        shadow->encryptedData.empty())
                        continue;

                    const uint64_t shadowStart =
                        shadow->dataOffset;
                    const uint64_t shadowEnd =
                        shadowStart +
                        static_cast<uint64_t>(
                            shadow->encryptedData.size());

                    const uint64_t overlapStart =
                        (std::max)(readStart, shadowStart);
                    const uint64_t overlapEnd =
                        (std::min)(readEnd, shadowEnd);

                    if (overlapStart >= overlapEnd)
                        continue;

                    const size_t destinationOffset =
                        static_cast<size_t>(
                            overlapStart - readStart);
                    const size_t sourceOffset =
                        static_cast<size_t>(
                            overlapStart - shadowStart);
                    const size_t copySize =
                        static_cast<size_t>(
                            overlapEnd - overlapStart);

                    std::memcpy(
                        buffer + destinationOffset,
                        shadow->encryptedData.data() +
                            sourceOffset,
                        copySize);

                    touched = true;

                    spdlog::info(
                        "IHTextureOverride: QAR READ OVERLAY "
                        "0x{:016x} via {} '{}' file+0x{:x}, "
                        "{} byte(s)",
                        shadow->pathHash, source,
                        shadow->archiveDisplay,
                        overlapStart, copySize);
                }

                return touched;
            }

            static bool IsStreamCaptureArmedLocked(void*& blockOut, uint64_t& hashOut) {
                blockOut = nullptr;
                hashOut = 0;

                if (asyncCaptureTargetBlock == nullptr ||
                    GetTickCount64() > asyncCaptureDeadlineMs)
                    return false;

                auto found = targetBlocks.find(asyncCaptureTargetBlock);
                if (found == targetBlocks.end() || found->second.patched)
                    return false;

                blockOut = asyncCaptureTargetBlock;
                hashOut = found->second.canonicalContainerHash;
                return true;
            }

            static std::string DescribeFileHandle(HANDLE file) {
                if (file == nullptr || file == INVALID_HANDLE_VALUE)
                    return "<invalid>";

                wchar_t path[1024]{};
                DWORD length = GetFinalPathNameByHandleW(
                    file, path, static_cast<DWORD>(std::size(path)), FILE_NAME_NORMALIZED);

                if (length == 0 || length >= std::size(path))
                    return "<unknown>";

                std::wstring ws(path, length);
                return std::string(ws.begin(), ws.end());
            }

            static bool ClaimRawReadBudget(size_t requested, size_t& scanLength,
                void*& targetBlock, uint64_t& targetHash) {
                std::lock_guard<std::mutex> lock(registryMutex);

                if (!IsStreamCaptureArmedLocked(targetBlock, targetHash))
                    return false;

                if (rawReadCallsScanned >= MaxRawReadCallsPerWindow ||
                    rawReadBytesScanned >= MaxRawReadBytesPerWindow)
                    return false;

                const size_t remaining =
                    MaxRawReadBytesPerWindow - rawReadBytesScanned;

                scanLength = (std::min)(
                    requested, (std::min)(remaining, MaxRawReadSingleScan));

                if (scanLength < 32)
                    return false;

                ++rawReadCallsScanned;
                rawReadBytesScanned += scanLength;
                return true;
            }

            static void MarkRawReadPatched(void* block) {
                std::lock_guard<std::mutex> lock(registryMutex);
                auto found = targetBlocks.find(block);
                if (found != targetBlocks.end())
                    found->second.patched = true;
            }

            static bool TryPatchRawReadBuffer(
                HANDLE file, uint8_t* buffer, size_t bytesRead,
                uint64_t fileOffset, bool hasFileOffset, const char* source) {

                if (buffer == nullptr || bytesRead < 32)
                    return false;

                size_t scanLength = 0;
                void* targetBlock = nullptr;
                uint64_t targetHash = 0;

                if (!ClaimRawReadBudget(
                    bytesRead, scanLength, targetBlock, targetHash))
                    return false;

                const uint8_t magicBytes[4] = {
                    'P', 'F', 'T', 'X'
                };

                size_t cursor = 0;
                while (cursor + 32 <= scanLength) {
                    const uint8_t* begin = buffer + cursor;
                    const uint8_t* end = buffer + scanLength;
                    const uint8_t* hit = std::search(
                        begin, end, std::begin(magicBytes), std::end(magicBytes));

                    if (hit == end)
                        break;

                    const size_t hitOffset =
                        static_cast<size_t>(hit - buffer);
                    const size_t remaining =
                        bytesRead - hitOffset;

                    if (remaining >= 32 &&
                        ReadU32(hit + 16) == TexlMagic) {

                        const uint32_t texlSize = ReadU32(hit + 20);
                        const size_t declaredTotal =
                            static_cast<size_t>(texlSize) + 16;

                        if (declaredTotal >= 32 &&
                            declaredTotal <= MaxPftxsSize &&
                            declaredTotal > remaining) {

                            bool shouldLog = false;
                            {
                                std::lock_guard<std::mutex> lock(registryMutex);
                                if (rawHeaderLogs < MaxRawHeaderLogs) {
                                    ++rawHeaderLogs;
                                    shouldLog = true;
                                }
                            }

                            if (shouldLog) {
                                spdlog::info(
                                    "IHTextureOverride: RAW PFTX header via {} in '{}' "
                                    "buffer+0x{:x}; declared {} bytes but only {} remain "
                                    "(file offset {})",
                                    source, DescribeFileHandle(file), hitOffset,
                                    declaredTotal, remaining,
                                    hasFileOffset
                                        ? fmt::format("0x{:x}", fileOffset + hitOffset)
                                        : std::string("<unknown>"));
                            }

                            cursor = hitOffset + 4;
                            continue;
                        }

                        if (declaredTotal >= 32 &&
                            declaredTotal <= remaining &&
                            declaredTotal <= MaxPftxsSize) {

                            std::vector<uint8_t> rebuilt;
                            size_t originalTotal = 0;
                            size_t replacedCount = 0;
                            std::string reason;

                            if (BuildPatchedPftxs(
                                hit, remaining, rebuilt, originalTotal,
                                replacedCount, reason)) {

                                spdlog::info(
                                    "IHTextureOverride: STREAM FOUND PFTXS 0x{:016x} "
                                    "via {} in '{}' at buffer+0x{:x} "
                                    "({} replacement(s), {} -> {} bytes)",
                                    targetHash, source, DescribeFileHandle(file),
                                    hitOffset, replacedCount,
                                    originalTotal, rebuilt.size());

                                if (rebuilt.size() > originalTotal) {
                                    spdlog::warn(
                                        "IHTextureOverride: STREAM cannot patch "
                                        "0x{:016x}: rebuilt PFTXS grows by {} bytes "
                                        "({} -> {})",
                                        targetHash,
                                        rebuilt.size() - originalTotal,
                                        originalTotal, rebuilt.size());
                                    return false;
                                }

                                std::memcpy(
                                    buffer + hitOffset,
                                    rebuilt.data(), rebuilt.size());

                                if (rebuilt.size() < originalTotal) {
                                    std::memset(
                                        buffer + hitOffset + rebuilt.size(), 0,
                                        originalTotal - rebuilt.size());
                                }

                                MarkRawReadPatched(targetBlock);

                                spdlog::info(
                                    "IHTextureOverride: STREAM MEMORY PATCHED "
                                    "container 0x{:016x} via {} "
                                    "({} replacement(s), {} -> {} bytes)",
                                    targetHash, source, replacedCount,
                                    originalTotal, rebuilt.size());
                                return true;
                            }
                        }
                    }

                    cursor = hitOffset + 4;
                }

                return false;
            }

            static bool CaptureCurrentFileOffset(HANDLE file, uint64_t& offset) {
                LARGE_INTEGER zero{};
                LARGE_INTEGER pos{};
                if (!SetFilePointerEx(file, zero, &pos, FILE_CURRENT))
                    return false;
                offset = static_cast<uint64_t>(pos.QuadPart);
                return true;
            }

            static void CompletePendingRead(
                LPOVERLAPPED overlapped, DWORD bytesTransferred,
                const char* source) {
                if (overlapped == nullptr || bytesTransferred == 0)
                    return;

                PendingRead pending;
                bool found = false;

                {
                    std::lock_guard<std::mutex> lock(pendingReadMutex);
                    auto it = pendingReads.find(overlapped);
                    if (it != pendingReads.end()) {
                        pending = it->second;
                        pendingReads.erase(it);
                        found = true;
                    }
                }

                if (!found || pending.buffer == nullptr)
                    return;

                const size_t length = (std::min)(
                    static_cast<size_t>(bytesTransferred),
                    static_cast<size_t>(pending.requested));

                OverlayQarShadow(
                    pending.file,
                    static_cast<uint8_t*>(pending.buffer),
                    length, pending.offset,
                    pending.hasOffset, source);

                TryPatchRawReadBuffer(
                    pending.file,
                    static_cast<uint8_t*>(pending.buffer),
                    length, pending.offset,
                    pending.hasOffset, source);
            }

            static BOOL WINAPI ReadFileHook(
                HANDLE file, LPVOID buffer, DWORD bytesToRead,
                LPDWORD bytesRead, LPOVERLAPPED overlapped) {

                if (insideStreamHook || ReadFileOriginal == nullptr)
                    return ReadFileOriginal(
                        file, buffer, bytesToRead, bytesRead, overlapped);

                insideStreamHook = true;

                bool captureArmed = false;
                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    void* block = nullptr;
                    uint64_t hash = 0;
                    captureArmed = IsStreamCaptureArmedLocked(block, hash);
                }

                const bool shouldTrack =
                    captureArmed ||
                    hasQarShadows.load(std::memory_order_acquire);

                PendingRead pending;
                if (shouldTrack && buffer != nullptr && bytesToRead != 0) {
                    pending.file = file;
                    pending.buffer = buffer;
                    pending.requested = bytesToRead;

                    if (overlapped != nullptr) {
                        pending.offset =
                            (static_cast<uint64_t>(overlapped->OffsetHigh) << 32) |
                            static_cast<uint64_t>(overlapped->Offset);
                        pending.hasOffset = true;

                        std::lock_guard<std::mutex> lock(pendingReadMutex);
                        pendingReads[overlapped] = pending;
                    } else {
                        pending.hasOffset =
                            CaptureCurrentFileOffset(file, pending.offset);
                    }
                }

                BOOL result = ReadFileOriginal(
                    file, buffer, bytesToRead, bytesRead, overlapped);

                DWORD error = result ? ERROR_SUCCESS : GetLastError();

                if (shouldTrack && buffer != nullptr) {
                    if (overlapped == nullptr) {
                        if (result && bytesRead != nullptr && *bytesRead != 0) {
                            OverlayQarShadow(
                                file, static_cast<uint8_t*>(buffer),
                                static_cast<size_t>(*bytesRead),
                                pending.offset, pending.hasOffset,
                                "ReadFile");

                            if (captureArmed) {
                                TryPatchRawReadBuffer(
                                    file, static_cast<uint8_t*>(buffer),
                                    static_cast<size_t>(*bytesRead),
                                    pending.offset, pending.hasOffset,
                                    "ReadFile");
                            }
                        }
                    } else if (result && bytesRead != nullptr &&
                        *bytesRead != 0) {
                        CompletePendingRead(
                            overlapped, *bytesRead,
                            "ReadFile-immediate");
                    } else if (!result && error != ERROR_IO_PENDING) {
                        std::lock_guard<std::mutex> lock(pendingReadMutex);
                        pendingReads.erase(overlapped);
                    }
                }

                if (!result)
                    SetLastError(error);

                insideStreamHook = false;
                return result;
            }

            static BOOL WINAPI GetOverlappedResultHook(
                HANDLE file, LPOVERLAPPED overlapped,
                LPDWORD bytesTransferred, BOOL wait) {

                BOOL result = GetOverlappedResultOriginal(
                    file, overlapped, bytesTransferred, wait);

                if (result && bytesTransferred != nullptr &&
                    *bytesTransferred != 0) {
                    CompletePendingRead(
                        overlapped, *bytesTransferred,
                        "GetOverlappedResult");
                }
                return result;
            }

            static BOOL WINAPI GetQueuedCompletionStatusHook(
                HANDLE completionPort, LPDWORD bytesTransferred,
                PULONG_PTR completionKey, LPOVERLAPPED* overlapped,
                DWORD milliseconds) {

                BOOL result = GetQueuedCompletionStatusOriginal(
                    completionPort, bytesTransferred, completionKey,
                    overlapped, milliseconds);

                if (overlapped != nullptr && *overlapped != nullptr &&
                    bytesTransferred != nullptr &&
                    *bytesTransferred != 0) {
                    CompletePendingRead(
                        *overlapped, *bytesTransferred,
                        "GetQueuedCompletionStatus");
                }
                return result;
            }

            static BOOL WINAPI GetQueuedCompletionStatusExHook(
                HANDLE completionPort, LPOVERLAPPED_ENTRY entries,
                ULONG count, PULONG removed, DWORD milliseconds,
                BOOL alertable) {

                BOOL result = GetQueuedCompletionStatusExOriginal(
                    completionPort, entries, count, removed,
                    milliseconds, alertable);

                if (result && entries != nullptr && removed != nullptr) {
                    for (ULONG i = 0; i < *removed; ++i) {
                        if (entries[i].lpOverlapped != nullptr &&
                            entries[i].dwNumberOfBytesTransferred != 0) {
                            CompletePendingRead(
                                entries[i].lpOverlapped,
                                entries[i].dwNumberOfBytesTransferred,
                                "GetQueuedCompletionStatusEx");
                        }
                    }
                }
                return result;
            }

            static void EnsureStreamHooks() {
                bool expected = false;
                if (!streamHooksInstalled.compare_exchange_strong(expected, true))
                    return;

                HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
                if (kernel32 == nullptr) {
                    spdlog::error(
                        "IHTextureOverride: stream probe could not resolve kernel32.dll");
                    streamHooksInstalled.store(false);
                    return;
                }

                struct HookSpec {
                    const char* name;
                    LPVOID target;
                    LPVOID hook;
                    LPVOID* original;
                };

                HookSpec hooks[] = {
                    {
                        "ReadFile",
                        reinterpret_cast<LPVOID>(
                            GetProcAddress(kernel32, "ReadFile")),
                        reinterpret_cast<LPVOID>(&ReadFileHook),
                        reinterpret_cast<LPVOID*>(&ReadFileOriginal)
                    },
                    {
                        "GetOverlappedResult",
                        reinterpret_cast<LPVOID>(
                            GetProcAddress(kernel32, "GetOverlappedResult")),
                        reinterpret_cast<LPVOID>(&GetOverlappedResultHook),
                        reinterpret_cast<LPVOID*>(&GetOverlappedResultOriginal)
                    },
                    {
                        "GetQueuedCompletionStatus",
                        reinterpret_cast<LPVOID>(
                            GetProcAddress(kernel32, "GetQueuedCompletionStatus")),
                        reinterpret_cast<LPVOID>(&GetQueuedCompletionStatusHook),
                        reinterpret_cast<LPVOID*>(&GetQueuedCompletionStatusOriginal)
                    },
                    {
                        "GetQueuedCompletionStatusEx",
                        reinterpret_cast<LPVOID>(
                            GetProcAddress(kernel32, "GetQueuedCompletionStatusEx")),
                        reinterpret_cast<LPVOID>(&GetQueuedCompletionStatusExHook),
                        reinterpret_cast<LPVOID*>(&GetQueuedCompletionStatusExOriginal)
                    },
                };

                size_t installed = 0;
                for (auto& spec : hooks) {
                    if (spec.target == nullptr)
                        continue;

                    MH_STATUS createStatus = MH_CreateHook(
                        spec.target, spec.hook, spec.original);

                    if (createStatus != MH_OK &&
                        createStatus != MH_ERROR_ALREADY_CREATED) {
                        spdlog::warn(
                            "IHTextureOverride: stream hook {} create failed ({})",
                            spec.name, static_cast<int>(createStatus));
                        continue;
                    }

                    MH_STATUS enableStatus = MH_EnableHook(spec.target);
                    if (enableStatus != MH_OK &&
                        enableStatus != MH_ERROR_ENABLED) {
                        spdlog::warn(
                            "IHTextureOverride: stream hook {} enable failed ({})",
                            spec.name, static_cast<int>(enableStatus));
                        continue;
                    }

                    ++installed;
                    spdlog::info(
                        "IHTextureOverride: stream hook enabled for {}",
                        spec.name);
                }

                if (installed == 0) {
                    streamHooksInstalled.store(false);
                    spdlog::error(
                        "IHTextureOverride: no stream read hooks could be installed");
                } else {
                    spdlog::info(
                        "IHTextureOverride: stream read probe active ({} hook(s))",
                        installed);
                }
            }

            static bool TryPatchExactSpan(const AllocationSpan& span, void* block,
                TargetBlockState& state, size_t& scannedBytes) {
                if (span.address == nullptr || span.size < 32)
                    return false;

                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQuery(span.address, &mbi, sizeof(mbi)) == 0 ||
                    mbi.State != MEM_COMMIT || !IsReadableProtection(mbi.Protect))
                    return false;

                const uint8_t* regionEnd = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (span.address < mbi.BaseAddress)
                    return false;

                const size_t regionRemaining = static_cast<size_t>(regionEnd - span.address);
                const size_t length = (std::min)(span.size, regionRemaining);
                if (length < 32)
                    return false;

                return TryPatchWindow(span.address, length, regionEnd, block, state, scannedBytes);
            }

            static bool TryPatchPointerOwner(void* owner, void* logicalBlock,
                TargetBlockState& state, size_t& scannedBytes, size_t& remainingBudget,
                std::unordered_set<void*>& seenRegions) {
                if (owner == nullptr || remainingBudget < 32)
                    return false;

                const uint8_t* ownerBytes = static_cast<const uint8_t*>(owner);
                MEMORY_BASIC_INFORMATION ownerMbi{};
                if (VirtualQuery(ownerBytes, &ownerMbi, sizeof(ownerMbi)) == 0 ||
                    ownerMbi.State != MEM_COMMIT || !IsReadableProtection(ownerMbi.Protect))
                    return false;

                const uint8_t* ownerRegionEnd =
                    static_cast<const uint8_t*>(ownerMbi.BaseAddress) + ownerMbi.RegionSize;
                const size_t availableOwnerBytes =
                    static_cast<size_t>(ownerRegionEnd - ownerBytes);
                const size_t probeBytes =
                    (std::min)(availableOwnerBytes, BlockPointerProbeBytes);

                for (size_t off = 0;
                    off + sizeof(uintptr_t) <= probeBytes && remainingBudget >= 32;
                    off += sizeof(uintptr_t)) {
                    uintptr_t value = 0;
                    std::memcpy(&value, ownerBytes + off, sizeof(value));
                    if (!IsPlausiblePointer(value))
                        continue;

                    const uint8_t* candidate = reinterpret_cast<const uint8_t*>(value);
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQuery(candidate, &mbi, sizeof(mbi)) == 0 ||
                        mbi.State != MEM_COMMIT || !IsReadableProtection(mbi.Protect) ||
                        mbi.Type == MEM_IMAGE)
                        continue;
                    if (!seenRegions.insert(mbi.BaseAddress).second)
                        continue;

                    const uint8_t* regionEnd =
                        static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                    if (candidate >= regionEnd)
                        continue;

                    size_t length = static_cast<size_t>(regionEnd - candidate);
                    length = (std::min)(length, remainingBudget);
                    if (length < 32)
                        continue;

                    if (TryPatchWindow(candidate, length, regionEnd,
                        logicalBlock, state, scannedBytes))
                        return true;

                    remainingBudget -= length;
                }
                return false;
            }

            static bool TryPatchFallbackPointers(void* block, TargetBlockState& state,
                size_t& scannedBytes) {
                size_t remainingBudget = MaxFallbackProbeBytes;
                std::unordered_set<void*> seenRegions;

                // BlockMemory is more likely than the fox::Block object to reference
                // the payload/arena used by the current load.
                if (TryPatchPointerOwner(state.blockMemory, block, state,
                    scannedBytes, remainingBudget, seenRegions))
                    return true;

                if (state.blockMemory != block &&
                    TryPatchPointerOwner(block, block, state,
                        scannedBytes, remainingBudget, seenRegions))
                    return true;

                return false;
            }

            static bool TryPatchTargetBlock(void* block, TargetBlockState& state) {
                size_t scannedBytes = 0;

                // Preferred path: only inspect allocations that Fox explicitly made for
                // this exact target block. This avoids the multi-megabyte arbitrary
                // VirtualQuery walk used by the first Phase 2 prototype.
                for (const auto& span : state.allocations) {
                    if (scannedBytes >= MaxAllocationScanBytes)
                        break;

                    AllocationSpan bounded = span;
                    const size_t remaining = MaxAllocationScanBytes - scannedBytes;
                    bounded.size = (std::min)(bounded.size, remaining);

                    if (TryPatchExactSpan(bounded, block, state, scannedBytes))
                        return true;
                }

                // Very small fallback probe in case this block uses a pre-existing arena
                // rather than BlockMemoryAllocTail. It is capped at 256 KiB total.
                if (state.allocations.empty()) {
                    if (TryPatchFallbackPointers(block, state, scannedBytes))
                        return true;

                    if (!state.fallbackLogged && state.processCalls >= 16) {
                        spdlog::debug(
                            "IHTextureOverride: target block {} has no recorded BlockMemoryAllocTail allocation yet; "
                            "fallback probe is capped at {} bytes",
                            block, MaxFallbackProbeBytes);
                        state.fallbackLogged = true;
                    }
                }

                if (state.processCalls == 1 || state.processCalls == 16 ||
                    state.processCalls == 64 || state.processCalls == 256) {
                    spdlog::debug(
                        "IHTextureOverride: target block {} process #{}: BlockMemory {}, "
                        "{} allocation(s), {} bytes scanned this pass",
                        block, state.processCalls, state.blockMemory,
                        state.allocations.size(), scannedBytes);
                }
                return false;
            }

        }//anonymous namespace

        int CreateLibs(lua_State* L) {
            spdlog::debug("Hooks_TextureOverride::CreateLibs");

            luaL_Reg libFuncs[] = {
                { "Register", l_Register },
                { "Clear", l_Clear },
                { "GetRegistrationCount", l_GetRegistrationCount },
                { NULL, NULL }
            };
            luaI_openlib(L, "IHTextureOverride", libFuncs, 0);
            return 1;
        }

        bool HasRegistrations() {
            return hasRegistrations.load(std::memory_order_acquire);
        }

        void NotifyPath(uint64_t pathCode) {
            if (pathCode == 0 || !HasRegistrations())
                return;

            std::vector<std::string> owners;
            uint64_t hitCount = 0;
            {
                std::lock_guard<std::mutex> lock(registryMutex);
                auto found = containerOwners.find(pathCode);
                if (found == containerOwners.end())
                    return;

                owners = found->second;
                hitCount = ++hitCounts[pathCode];
            }

            const std::string ownerText = JoinOwners(owners);
            if (hitCount == 1) {
                spdlog::info("IHTextureOverride: container hit 0x{:016x} [{}]",
                    pathCode, ownerText);
            }
            else {
                spdlog::debug("IHTextureOverride: container hit 0x{:016x} #{} [{}]",
                    pathCode, hitCount, ownerText);
            }
        }

        void NotifyBlockLoad(void* block, const uint64_t* pathCodes, uint32_t count) {
            if (block == nullptr || pathCodes == nullptr || count == 0 || !HasRegistrations())
                return;

            for (uint32_t i = 0; i < count; ++i) {
                const uint64_t raw = pathCodes[i];
                const uint64_t key = raw & FoxBlockPathMask;

                uint64_t canonicalHash = 0;
                std::string ownerText;
                bool targetMatched = false;

                {
                    std::lock_guard<std::mutex> lock(registryMutex);
                    auto found = containerLoadIndex.find(key);
                    if (found == containerLoadIndex.end() || found->second.empty())
                        continue;

                    canonicalHash = found->second.front();
                    auto ownerIt = containerOwners.find(canonicalHash);
                    if (ownerIt != containerOwners.end())
                        ownerText = JoinOwners(ownerIt->second);

                    auto& state = targetBlocks[block];
                    const bool firstAssociation =
                        state.canonicalContainerHash == 0;

                    if (state.blockMemory != nullptr) {
                        auto reverseIt =
                            blockMemoryOwners.find(state.blockMemory);
                        if (reverseIt != blockMemoryOwners.end() &&
                            reverseIt->second == block) {
                            blockMemoryOwners.erase(reverseIt);
                        }
                    }

                    state.canonicalContainerHash = canonicalHash;
                    state.rawLoadId = raw;
                    state.owners = ownerText;
                    state.processCalls = 0;
                    state.blockMemory = nullptr;
                    state.lastScannedAllocationCount = 0;
                    state.allocations.clear();
                    state.patched = false;
                    state.growthFailureLogged = false;
                    state.noBufferLogged = false;
                    state.fallbackLogged = false;

                    asyncCaptureTargetBlock = block;
                    asyncCaptureDeadlineMs =
                        GetTickCount64() + AsyncCaptureWindowMs;
                    asyncCaptureCount = 0;
                    asyncCaptureBytes = 0;
                    asyncCaptureLogged = 0;
                    rawReadCallsScanned = 0;
                    rawReadBytesScanned = 0;
                    rawHeaderLogs = 0;

                    hasTargetBlocks.store(
                        true, std::memory_order_release);

                    spdlog::info(
                        "IHTextureOverride: armed target I/O capture for block {} "
                        "for {} ms [{}]",
                        block, AsyncCaptureWindowMs, ownerText);

                    if (firstAssociation) {
                        spdlog::info(
                            "IHTextureOverride: target block {} raw "
                            "0x{:016x} -> container 0x{:016x} [{}]",
                            block, raw, canonicalHash, ownerText);
                    }

                    targetMatched = true;
                }

                // This runs before the original FoxBlockLoad. Build only the shadow
                // for the container that is actually being requested, so startup
                // stays cheap and we don't hold hundreds of MB of unused PFTXS data.
                if (targetMatched)
                    EnsureQarShadowPrepared(canonicalHash);
            }
        }

        bool EnterBlockProcess(void* block, void* processBlockMemory) {
            if (!hasTargetBlocks.load(std::memory_order_acquire))
                return false;

            void* targetForThisScope = nullptr;

            {
                std::lock_guard<std::mutex> lock(registryMutex);
                auto found = targetBlocks.find(block);
                if (found != targetBlocks.end() && !found->second.patched) {
                    targetForThisScope = block;

                    if (processBlockMemory != nullptr &&
                        found->second.blockMemory != processBlockMemory) {
                        if (found->second.blockMemory != nullptr) {
                            auto old = blockMemoryOwners.find(found->second.blockMemory);
                            if (old != blockMemoryOwners.end() && old->second == block)
                                blockMemoryOwners.erase(old);
                        }

                        found->second.blockMemory = processBlockMemory;
                        blockMemoryOwners[processBlockMemory] = block;

                        spdlog::info(
                            "IHTextureOverride: target scope block {} "
                            "ProcessMemory {} [{}]",
                            block, processBlockMemory, found->second.owners);
                    }
                }
            }

            // Push nullptr for non-target nested Process calls so allocations made by
            // them are never accidentally charged to an outer target Process.
            processingTargetStack.push_back(targetForThisScope);
            return true;
        }

        void LeaveBlockProcess() {
            if (!processingTargetStack.empty())
                processingTargetStack.pop_back();
        }

        void NotifyBlockAllocation(void* blockMemory, void* allocation,
            uint64_t sizeInBytes, uint64_t alignment, uint32_t categoryTag) {
            if (allocation == nullptr || sizeInBytes == 0 ||
                !hasTargetBlocks.load(std::memory_order_acquire))
                return;

            std::lock_guard<std::mutex> lock(registryMutex);

            void* block = nullptr;

            // Primary association: allocation occurred synchronously inside the
            // currently executing target FoxBlockLoad/FoxBlockProcess on this thread.
            if (!processingTargetStack.empty() &&
                processingTargetStack.back() != nullptr) {
                block = processingTargetStack.back();
            }

            // Secondary association in case Fox calls the allocator just outside the
            // direct Process frame but reuses the ProcessMemory object.
            if (block == nullptr && blockMemory != nullptr) {
                auto ownerIt = blockMemoryOwners.find(blockMemory);
                if (ownerIt != blockMemoryOwners.end())
                    block = ownerIt->second;
            }

            bool asyncAssociation = false;

            // The asset streamer may perform the actual allocation on a worker
            // thread after FoxBlockLoad returns. While a target request is armed,
            // accept only reasonably large allocations and enforce hard count/byte
            // limits. The PFTX parser later rejects unrelated buffers.
            if (block == nullptr &&
                asyncCaptureTargetBlock != nullptr &&
                GetTickCount64() <= asyncCaptureDeadlineMs &&
                sizeInBytes >= AsyncMinAllocationSize &&
                asyncCaptureCount < MaxAsyncAllocations &&
                asyncCaptureBytes < MaxAsyncCapturedBytes) {

                const size_t proposedSize = sizeInBytes > static_cast<uint64_t>(SIZE_MAX)
                    ? SIZE_MAX
                    : static_cast<size_t>(sizeInBytes);

                if (proposedSize <= MaxAsyncCapturedBytes - asyncCaptureBytes) {
                    block = asyncCaptureTargetBlock;
                    asyncAssociation = true;
                    ++asyncCaptureCount;
                    asyncCaptureBytes += proposedSize;
                }
            }

            if (block == nullptr)
                return;

            auto found = targetBlocks.find(block);
            if (found == targetBlocks.end() || found->second.patched)
                return;

            const size_t size = sizeInBytes > static_cast<uint64_t>(SIZE_MAX)
                ? SIZE_MAX
                : static_cast<size_t>(sizeInBytes);

            for (auto& existing : found->second.allocations) {
                if (existing.address == allocation) {
                    if (size > existing.size)
                        existing.size = size;
                    return;
                }
            }

            AllocationSpan span;
            span.address = static_cast<uint8_t*>(allocation);
            span.size = size;
            span.alignment = alignment;
            span.categoryTag = categoryTag;
            found->second.allocations.push_back(span);

            const char* source =
                blockMemory == nullptr ? "heap" : "tail";

            if (!asyncAssociation || asyncCaptureLogged < 32) {
                spdlog::info(
                    "IHTextureOverride: TARGET ALLOCATION block {} via {}{} mem {} -> {} "
                    "size {} align {} tag 0x{:08x} [{}]",
                    block, asyncAssociation ? "ASYNC-" : "", source,
                    blockMemory, allocation, size,
                    alignment, categoryTag, found->second.owners);
                if (asyncAssociation)
                    ++asyncCaptureLogged;
            }
        }

        void ProcessBlock(void* block) {
            if (block == nullptr || !hasTargetBlocks.load(std::memory_order_acquire))
                return;

            TargetBlockState state;
            bool shouldScan = false;
            {
                std::lock_guard<std::mutex> lock(registryMutex);
                auto found = targetBlocks.find(block);
                if (found == targetBlocks.end() || found->second.patched)
                    return;

                ++found->second.processCalls;
                if (found->second.processCalls > MaxProcessCalls) {
                    if (!found->second.noBufferLogged) {
                        spdlog::warn(
                            "IHTextureOverride: target block {} for 0x{:016x} never exposed a patchable raw PFTX "
                            "after {} Process calls (BlockMemory {}, {} allocation(s) observed; "
                            "async capture {} allocation(s), {} bytes)",
                            block, found->second.canonicalContainerHash, MaxProcessCalls,
                            found->second.blockMemory, found->second.allocations.size(),
                            asyncCaptureCount, asyncCaptureBytes);
                        found->second.noBufferLogged = true;
                    }
                    return;
                }

                const bool hasNewAllocation =
                    found->second.allocations.size() != found->second.lastScannedAllocationCount;

                // New allocations get inspected immediately. Without a new allocation,
                // only sample a few process milestones so asynchronous fills can complete
                // without putting a large scan on every frame/load tick.
                const uint64_t n = found->second.processCalls;
                shouldScan = hasNewAllocation || n == 1 || n == 4 || n == 16 ||
                    n == 64 || n == 256;

                if (shouldScan)
                    found->second.lastScannedAllocationCount = found->second.allocations.size();

                state = found->second;
            }

            if (!shouldScan)
                return;

            const bool patched = TryPatchTargetBlock(block, state);

            {
                std::lock_guard<std::mutex> lock(registryMutex);
                auto found = targetBlocks.find(block);
                if (found != targetBlocks.end()) {
                    found->second.growthFailureLogged =
                        found->second.growthFailureLogged || state.growthFailureLogged;
                    found->second.fallbackLogged =
                        found->second.fallbackLogged || state.fallbackLogged;
                    if (patched)
                        found->second.patched = true;
                }
            }
        }

    }//namespace Hooks_TextureOverride
}//namespace IHHook
