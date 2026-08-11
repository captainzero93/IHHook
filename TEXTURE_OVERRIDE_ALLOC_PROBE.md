# IHTextureOverride Phase 2 allocation-probe build

This replaces the first Phase 2 prototype's broad VirtualQuery memory walk.

Expected log progression:

- `IHTextureOverride: registered ... (4 loaded, ...)`
- `IHTextureOverride: target block ...`
- one or more `IHTextureOverride: target allocation block ...`
- then either:
  - `IHTextureOverride: found PFTXS ...`
  - `IHTextureOverride: MEMORY PATCHED ...`
  - `IHTextureOverride: cannot patch ... grows by ...`
  - or a bounded diagnostic saying no patchable PFTX was exposed.

The hot FoxBlockProcess hook no longer scans tens of megabytes per call.
