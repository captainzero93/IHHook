# IHTextureOverride Phase 2 - Load-scope allocator build

Result from previous stable build:
- target Quiet PFTXS block detected
- FoxBlockProcess target scope entered
- zero BlockMemoryAllocTail allocations through Process #256

Inference:
The raw PFTXS/file buffer may be allocated during fox::Block::Load rather than
fox::Block::Process.

This build:
1. NotifyBlockLoad associates the target block.
2. A per-thread target scope is pushed BEFORE the original FoxBlockLoad.
3. BlockMemoryAllocTail calls made synchronously inside Load are captured.
4. ProcessBlock scans captured allocations immediately AFTER Load returns.
5. The Process-phase scope remains as a second chance.
6. No GetCurrentBlockMemory/TLS helper is present.
7. No broad multi-megabyte memory walk is present.

Fingerprint:
IHTextureOverride BUILD: LOAD_SCOPE_SAFE_NO_TLS_20260810_1142
