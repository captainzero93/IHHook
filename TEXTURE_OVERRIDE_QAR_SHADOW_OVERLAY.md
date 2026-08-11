# IHTextureOverride Phase 2 - QAR shadow overlay

Observed result from the ReadFile stream probe:
- ReadFile/GetOverlappedResult/GetQueuedCompletionStatus hooks installed correctly.
- Quiet `_04` target request detected.
- No literal PFTX/TEXL header appeared in raw OS read buffers.

Fox_Parser's QAR implementation explains why:
- `.pftxs` QAR entries are normally stored rather than zlib-compressed.
- QAR entry data still goes through Decrypt1 and may also go through Decrypt2.

This build therefore does not search for plaintext PFTX in the encrypted archive stream.

At manifest registration:
1. Scan QAR headers and encrypted section lists under the game directory.
2. Use the section's 40-bit path signature to cheaply shortlist only headers capable
   of matching one of the registered PFTXS PathCode64 values.
3. Store physical QAR locations for exact matching target hashes.

When Fox requests a registered PFTXS:
1. Read only that QAR entry from disk.
2. Decrypt QAR Decrypt1.
3. Parse/remove the optional QAR data header and Decrypt2.
4. Rebuild the plaintext PFTXS with the registered loose FTEX/FTEXS.
5. If the rebuilt PFTXS fits in the original outer QAR payload, pad it to the
   original capacity.
6. Reapply Decrypt2 and Decrypt1 using the ORIGINAL QAR MD5 seed/key.
7. Keep the QAR entry header and sizes unchanged.
8. ReadFile completion hooks overlay the same-size encrypted shadow bytes whenever
   the game reads that physical QAR entry.

No archive is modified on disk.

Important limitation:
If the rebuilt PFTXS exceeds the original QAR payload capacity, this build logs the
growth and does not patch it. A later redirection path would be needed for growth.

Fingerprint:
IHTextureOverride BUILD: QAR_SHADOW_OVERLAY_NO_TLS_20260810_1248

Key logs:
- `IHTextureOverride: QAR index scanned ...`
- `IHTextureOverride: QAR SHADOW READY ...`
- `IHTextureOverride: QAR READ OVERLAY ...`

If the overlay works but Fox rejects the data, the likely remaining boundary is an
integrity check using the original QAR MD5. At that point the hook needs to move
after QAR decryption or patch the cached entry metadata.
