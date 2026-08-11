# IHTextureOverride Phase 2 - bounded asynchronous allocator capture

Previous evidence:
- target Quiet PFTXS _04 detected
- Load scope active
- Process scope active
- BlockMemoryAllocTail and BlockMemoryAllocHeap hooks both active
- zero target allocations while those synchronous scopes were active

This build assumes the actual asset allocation/fill may occur on an asynchronous
worker thread after FoxBlockLoad schedules the request.

When a registered PFTXS is requested it arms a 5-second capture window:
- Tail and Heap allocations may be associated from any thread
- only allocations >= 64 KiB are considered
- maximum 256 allocations
- maximum 128 MiB total captured allocation size
- only exact returned allocations are scanned
- per scan pass remains capped at 32 MiB
- unrelated buffers are rejected by the PFTX/TEXL parser
- no GetCurrentBlockMemory/TLS helper
- no broad process-memory scan

Fingerprint:
IHTextureOverride BUILD: ASYNC_CAPTURE_SAFE_NO_TLS_20260810_1203

Useful expected lines:
IHTextureOverride: armed async allocation capture ...
IHTextureOverride: TARGET ALLOCATION ... via ASYNC-tail ...
or
IHTextureOverride: TARGET ALLOCATION ... via ASYNC-heap ...
then ideally:
IHTextureOverride: found PFTXS ...
