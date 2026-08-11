# IHTextureOverride canary patch (phase 1)

This patch is the native half expected by `modbldr-tools replaceall -ihhook` up to the point of runtime container detection.
It **does not modify or rebuild PFTXS bytes yet**.

## What it adds

- Global Lua library `IHTextureOverride`.
- `IHTextureOverride.Register(manifest)` parses the generated manifest from `GameDir/mod/modules/<name>.lua`.
- All texture and container `PathCode64` values are read from strings, avoiding Lua number precision loss.
- Registered container hashes are indexed natively.
- `Hooks_LoadFile::UpdateLocalPathStringHook` checks both observed PathCode64 arguments against that index.
- First hit for a registered container is written to `ihhook_log.txt` at info level.
- Subsequent hits are debug level to avoid log spam.

## Expected first test

Generate the Quiet hair runtime package with the patched Fox_Parser tool and copy the package contents into `MGS_TPP`.
The generated Lua must land at:

    GameDir/mod/modules/<ModuleName>.lua

On module load, `ihhook_log.txt` should contain something like:

    IHTextureOverride: registered 'QuietHairOverride' (4 texture file(s), 25 container(s))

When the known canary container is requested:

    /Assets/tpp/pack/buddy/quiet/buddy_quiet2_04.pftxs
    0xb2f8417c52767792

`ihhook_log.txt` should contain:

    IHTextureOverride: container hit 0xb2f8417c52767792 [QuietHairOverride]

At that point Lua -> C++ registration and runtime PathCode64 interception are proven.
The next phase is finding the PFTXS data pointer/length and replacing/rebuilding the matching FTEX/FTEXS entries in memory.

## Lua API added

    IHTextureOverride.Register(manifest) -> true
    IHTextureOverride.Clear()
    IHTextureOverride.GetRegistrationCount() -> integer

The generated Fox_Parser manifest already calls `IHTextureOverride.Register(this)`.

## Build

Use the normal IHHook Visual Studio solution/project and build the x64 configuration you normally install (Release, Release ASI, or Release Plugin).
The new source files are included in `IHHook.vcxproj` and `IHHook.vcxproj.filters`.
