# IHTextureOverride Phase 2 - ReadFile stream probe

Evidence from the previous async allocator build:
- correct Quiet `_04` PFTXS target detected
- 5-second async capture armed twice
- zero Tail/Heap target allocations
- no PFTXS memory image found

This build stops using allocator detours and moves lower into the Windows file-I/O path.

After a texture override manifest registers, it lazily hooks:
- ReadFile
- GetOverlappedResult
- GetQueuedCompletionStatus
- GetQueuedCompletionStatusEx

The hooks do almost nothing unless a registered target PFTXS request is armed.

During the 5-second target window:
- exact returned read buffers are scanned for `PFTX` + `TEXL`
- max 1024 read buffers
- max 256 MiB total scanned
- max 32 MiB from any single read buffer
- no process-wide VirtualQuery scan
- no GetCurrentBlockMemory / TLS helper

If a complete matching PFTXS is present in one returned read buffer, the existing
rebuild code patches it in place before Fox consumes it, provided the rebuilt
container does not grow.

Useful lines:
- `IHTextureOverride: stream read probe active`
- `IHTextureOverride: RAW PFTX header ...` (means the archive read contains a PFTXS,
  but the read buffer only contains part of it)
- `IHTextureOverride: STREAM FOUND PFTXS ...`
- `IHTextureOverride: STREAM MEMORY PATCHED ...`
- `IHTextureOverride: STREAM cannot patch ... grows ...`

Fingerprint:
`IHTextureOverride BUILD: READFILE_STREAM_PROBE_NO_TLS_20260810_1216`
