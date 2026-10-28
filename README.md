# Trident side-load canary

One lab action. A Microsoft-signed `where.exe`, copied out of `System32`, loads an unsigned `version.dll` from that same folder. The DLL writes one marker file next to them.

That is the shape in the hunt: signed image, unsigned DLL from the EXE directory, third file in the same directory and the same window.

`where.exe` imports `version.dll`, and `version.dll` is not a KnownDLL. The application directory is searched first. The copy in `run\` gets this DLL. The real `where.exe` in `System32` is not touched.

This does not patch an entry point, decrypt a blob, or drop `K7AVWScn.doc`. A rule that only matches those names will stay quiet. A rule on `payload.dat` or `trident_loader.dll` will stay quiet too.

## Run

From this folder, in a normal command prompt:

```bat
run.bat
```

`run.bat` builds `version_canary.dll` with VS 2026 (`vcvars64` if `cl` is not already on PATH), then fills `run\`:

| File | What it is |
|---|---|
| `where.exe` | Copy of `%SystemRoot%\System32\where.exe`. Signature should still say Microsoft Windows, status Valid. |
| `version.dll` | The unsigned canary. Same bytes as `version_canary.dll`. |
| `LAB-TRIDENT-SIDELOAD-<utc>.txt` | The marker. Written from `DllMain` when the DLL loads. The file name and the first line are the canary. |

`where.exe` with no arguments prints its usage and exits. Exit code 2 is that usage path. The load already happened.

The console prints the canary, the three paths, and the signature check.

## What to search

Ingest can lag. Wait 15–30 minutes before calling an empty search a miss. Longer if the pipeline is slow.

Search the canary string. It is on the marker file name and inside the file.

Then the load itself:

- Process create. Image ends with `\run\where.exe`. Signed, Microsoft, Valid. Path is not `System32`.
- Image load. ImageLoaded ends with `\run\version.dll`. Same directory as the EXE. No signature.
- File create. TargetFilename ends with the canary `.txt`. Same directory, same few seconds. The creating process is that `where.exe`.

`where.exe` also loads the usual `System32` DLLs. Those are not the canary. The unsigned `version.dll` under `run\` is.

Event ID 7 has to be collected. If image loads are dropped, you get the process and the marker file, and no DLL line. That is a collector gap, not a failed run.

A rule that fires on every `version.dll` outside `System32` will fire here and will also fire on installers and updaters. The useful check is the three things together: signed EXE under a non-install path, unsigned DLL with a name that belongs in `System32`, third file in that directory in the same window.

## What this is not

The DLL forwards `GetFileVersionInfoSizeExW`, `GetFileVersionInfoExW`, and `VerQueryValueW` to `%SystemRoot%\System32\version.dll` so the copied host can start. Nothing else is forwarded. There is no network, no service, no Run key, no second stage.

Delete `run\` when you are done. Build again with `build.bat` if you only want the DLL.
