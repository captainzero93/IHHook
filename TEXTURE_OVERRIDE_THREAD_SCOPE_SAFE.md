# IHTextureOverride Phase 2 - safe thread-scope allocator build

The prior TLS-context build crashed during boot before smallharr.lua registered.
It called the unverified GetCurrentBlockMemory helper from every FoxBlockProcess.

This build removes all calls to GetCurrentBlockMemory.

Instead:
1. FoxBlockLoad identifies the target fox::Block.
2. FoxBlockProcess pushes a per-thread scope only after texture registrations exist.
3. Nested non-target Process calls push nullptr so they cannot inherit target ownership.
4. BlockMemoryAllocTail attributes allocations made while the target scope is active.
5. The existing bounded PFTXS parser/rebuilder scans only captured allocations.

Expected:
- normal boot
- IHTextureOverride: registered ...
- IHTextureOverride: target block ...
- IHTextureOverride: target process scope block ...
- ideally IHTextureOverride: TARGET ALLOCATION ...
