# IHTextureOverride Phase 2 - heap capture build

Previous result:
- target PFTXS detected
- Load scope executed
- Process scope executed through #256
- zero BlockMemoryAllocTail allocations

Fox has two relevant allocator branches:
- BlockMemory::AllocTail
- BlockMemory::AllocHeap

This build keeps the Tail hook and adds the Heap hook at the existing
1.0.15.4 EN address 0x143261bf0.

Heap allocations are only retained if they occur while the current thread is
inside a registered target FoxBlockLoad/FoxBlockProcess scope. There is:
- no GetCurrentBlockMemory call
- no TLS helper
- no broad memory walk

Expected new line if the PFTXS uses the heap branch:
IHTextureOverride: TARGET ALLOCATION block ... via heap ...

Fingerprint:
IHTextureOverride BUILD: HEAP_CAPTURE_SAFE_NO_TLS_20260810_1150
