# IHTextureOverride Phase 2 - BlockMemory binding build

The allocation hook was active in the previous build, but the code compared
BlockMemoryAllocTail's BlockMemory* against FoxBlockLoad's fox::Block*.
Those are different pointers, so the target allocation count stayed at zero.

This build binds fox::Block* -> BlockMemory* in FoxBlockProcess before the
original process call, then reverse-resolves BlockMemoryAllocTail allocations
back to the target block.

Expected new lines:
IHTextureOverride: bound target block ... -> BlockMemory ...
IHTextureOverride: target allocation block ... BlockMemory ... -> ... size ...

The broad memory walk remains removed.
