# Steam P1 fixtures (Windows run only)

Create a **new** directory inside the PC run's scratch directory. The generator refuses an
existing destination and never reads the registry or real Steam directories:

```powershell
node desktop/native/sandbox/test-fixtures/make-steam-layout.mjs C:\YGAgentTest\steam-p1-fake
```

Point the test Steam reader at the printed `root`. The fake library contains app 976730, fully
installed (`StateFlags` 4), build 424242, in `steamapps/common/YG Steam Probe MCC`. Its
`halo3/halo3.dll` is a text stub over 64 bytes, with no executable code or Steam API.

Build `steam-probe` using the sandbox CMake project. Place `steam-probe.exe` in the test build's
own folder with this `yougame-native.json` (replace `GRANTED_DOCUMENTS_FOLDER` with the resolved
Windows path for exactly `documents/My Games/YG Steam Probe`, escaping backslashes for JSON):

```json
{
  "version": 1,
  "args": ["--base", "{base}", "--data", "{data}", "--documents", "GRANTED_DOCUMENTS_FOLDER"],
  "net": "none",
  "base": {"steam": 976730, "buildids": ["424242"], "files": ["halo3/halo3.dll"]},
  "folders": ["documents/My Games/YG Steam Probe"],
  "children": 1
}
```

The app supplies `YOUGAME_BASE_DIR` and `YOUGAME_DATA`; the explicit args above also work. Data
must be the listing's own LocalAppData data directory, and the Documents folder must already be
created and granted by the app. Do not pass the launcher's redirected `LOCALAPPDATA` as the
listing's data directory. The probe never creates folders or enumerates user files.

Expected JSON lines: `base_read` allowed with `bytes:64`; `base_write` denied with error 5;
`data_write` and `documents_write` allowed with `bytes:5`; `spawn_child` allowed; `child` allowed.
Parent and child stdout lines may interleave. Remove `children` from the spec and repeat:
`spawn_child` must be denied (normally error 367), with no `child` line. The process exits 0 when
the file checks match and the child either exits successfully or is blocked by process policy.
It exits 1 for an unexpected check result, or 2 for invalid arguments.

The probe uses `CREATE_NEW` and removes only its own temporary files. It does not call Steam,
access the network, modify registry discovery, or start the Steam client. Fake-layout app runs
are deliberately separate from the launcher's native CTests and from this Mac implementation run.
