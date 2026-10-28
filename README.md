# Trident side-load canary

One lab action. Stage three files, then start the signed host.

The host is a copy of Microsoft-signed `where.exe`, outside `System32`. It imports `version.dll`. That DLL is not a KnownDLL, so the loader takes the unsigned copy sitting in the same folder. `where.dat` is already there. `cmd.exe` wrote it before the process started.

Checked on Windows 11 Pro 26H2, build 26300.9711. `Win32_OperatingSystem` is the caption to trust. `ProductName` in the registry still says `Windows 10 Pro` on that image.

`where.exe` there is file version `10.0.26100.1`, the same binary shipped for Windows 11 24H2 and 25H2. SHA256 `F51FAB8041E5023D7290B540A2106F051EF0BD2BC3443C9DAF318628B560FA29`. It statically imports `GetFileVersionInfoSizeExW`, `GetFileVersionInfoExW`, and `VerQueryValueW` from `VERSION.dll`.

The same three imports are on the x64 `where.exe` from the other current Windows 11 lines:

| Windows 11 | `where.exe` | Imports from `VERSION.dll` |
|---|---|---|
| 21H2 (`10.0.22000.2600`) | x64 | those three |
| 22H2 and 23H2 (`10.0.22621.1`) | x64 | those three |
| 24H2 and 25H2 (`10.0.26100.1`) | x64 | those three |
| 26H2 build 26300.9711 | same file as 24H2/25H2 | those three |

`run.bat` copies `System32\where.exe` from the machine you run it on. A 22H2 lab and a 25H2 lab each get a host that matches that image. The canary DLL is x64 and forwards those three names to that machine's `System32\version.dll`.

ARM64 Windows 11 is a different `where.exe`. This DLL will not load into it. `SysWOW64\where.exe` will not load it either.

Smart App Control or a WDAC policy in enforcement can block the unsigned `version.dll` before the host runs it. The canary line never shows, and the DLL may still be in the folder. That is the control. Defender quarantine is the other common reason for a missing line.

On an image that is not in the table, check the import table before you call an empty run a miss:

```text
dumpbin /imports %SystemRoot%\System32\where.exe
```

Those three names have to be under `VERSION.dll`. If they are gone, this host will not side-load.

That is the log shape from the side-load step. Signed image, wrong directory. Unsigned DLL from that directory. A third file in the same folder, created by the stager, not by the host.

Search the canary. It is the directory name, and the first line of `where.dat`. File contents are usually not in the Sysmon event. The path is.

## Run

```bat
run.bat
```

Needs the VS 2026 x64 compiler. `build.bat` calls `vcvars64` if `cl` is not already on PATH. The DLL is x64 and matches `System32\where.exe`. `SysWOW64\where.exe` will not load it. Python is not used.

The run folder looks like this:

```text
run\LAB-TRIDENT-SIDELOAD-<utc>\
    where.exe     copy of %SystemRoot%\System32\where.exe
    version.dll   unsigned canary
    where.dat     plaintext marker, written by cmd.exe
```

`where.exe` with no arguments prints its usage and exits 2. Before that, the console should show one line from the DLL: `<canary> version.dll loaded from the EXE directory`. If that line is missing, look in the canary folder. Defender quarantines an unsigned `version.dll` next to a signed Microsoft binary, and then there is nothing to load. If `version.dll` is still on disk and the line is missing, the copy loaded `System32\version.dll` and this run did not do the side-load.

After the process exits, a dialog titled `LAB-TRIDENT-SIDELOAD` stays up until you click OK. It lists the canary, the folder, `where.exe`, `version.dll`, and `where.dat`.

The real `where.exe` in `System32` is not modified.

## What you should see

Ingest lags. Wait 15–30 minutes before an empty search is a miss. Longer if the pipeline is slow.

Event ID 7 has to be on. If image loads are dropped, you get the process and the file, and no DLL. That is a collector gap.

| Event | What | Who |
|---|---|---|
| 11 File create | `where.exe`, `version.dll`, `where.dat` under the canary directory | `cmd.exe` |
| 1 Process create | Image ends with `\<canary>\where.exe`. Signature Valid, Microsoft Windows. Path is not `System32`. `OriginalFileName` stays `where.exe` if the copy is renamed. This run keeps the name. | `where.exe` |
| 7 Image load | ImageLoaded ends with `\<canary>\version.dll`. Same directory as the EXE. Not signed. | `where.exe` |

`where.exe` also loads normal DLLs from `System32`. Leave those. The unsigned `version.dll` under the canary directory is the one.

A rule that only matches `trident_host.exe`, `trident_loader.dll`, `payload.dat`, `winfsp-x64.dll`, `DukeQt.dll`, or `K7AVWScn.doc` stays quiet. This run does not use those names.

A rule that needs `where.exe` to create `where.dat` also stays quiet. The file is already on disk when the process starts. That is the staging order.

## If nothing you have fires

Logging first. Search the canary with no rule around it.

```text
LAB-TRIDENT-SIDELOAD-
```

You want three hits for that directory: process image, loaded image, target filename. One or two hits means a collector gap, not a bad rule.

If the three events are there and no detection fired, the rule below is the one this test can support. It is Elastic KQL aimed at Winlogbeat-style fields. If your documents use `dll.path` and `process.executable` instead of `winlog.event_data.*`, swap the field names after you open one Event ID 7 from this run.

Lab check, this canary only:

```text
winlog.event_data.Image: *LAB-TRIDENT-SIDELOAD*\\where.exe
or winlog.event_data.ImageLoaded: *LAB-TRIDENT-SIDELOAD*\\version.dll
or winlog.event_data.TargetFilename: *LAB-TRIDENT-SIDELOAD*\\where.dat
```

Detection, same shape, not tied to the canary name:

```text
event.code: "7" and
winlog.event_data.Image: *\\where.exe and
not winlog.event_data.Image: *\\Windows\\System32\\* and
not winlog.event_data.Image: *\\Windows\\SysWOW64\\* and
winlog.event_data.ImageLoaded: *\\version.dll and
not winlog.event_data.ImageLoaded: *\\Windows\\System32\\* and
not winlog.event_data.ImageLoaded: *\\Windows\\SysWOW64\\*
```

Pair it with the file, same host, same directory, a few minutes either side:

```text
event.code: "11" and
winlog.event_data.TargetFilename: *\\where.dat and
not winlog.event_data.TargetFilename: *\\Windows\\System32\\*
```

`version.dll` outside `System32` will also show up from portable tools and updaters. Keep the signed-host path and the same directory in the query. A hit on the DLL name alone is not this test.

Sysmon XML cannot express "same directory" by itself. The join is in the search.

## What this is not

No patched `.text`, no jump over `WinMain`, no decrypted PE, no service, no Run key. Those do not show up in Event IDs 1, 7, or 11. The DLL only forwards `GetFileVersionInfoSizeExW`, `GetFileVersionInfoExW`, and `VerQueryValueW` to `%SystemRoot%\System32\version.dll`.

Delete `run\` when you are done.
