# Safe fingerprint build

This build contains NO GetCurrentBlockMemory symbol/reference in IHHook source.

Expected startup fingerprint:
IHTextureOverride BUILD: THREADSCOPE_SAFE_NO_TLS_20260810_1135

Expected Lua-library fingerprint after Lua initializes:
IHTextureOverride BUILD ACTIVE: THREADSCOPE_SAFE_NO_TLS_20260810_1135

If a runtime log still says:
isTargetExe, rebasing addr GetCurrentBlockMemory

then the running dinput8.dll was not built from this repository tree.
