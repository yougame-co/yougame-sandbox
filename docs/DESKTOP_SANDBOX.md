# Desktop game sandbox

Luis, 2026-10-01: "I don't think it's reasonable to expect all remixes to have a signature, but we
can do a lot with sandboxing. The goal should be that if a game runs inside of yougame it's
sandboxed and has much lower chance of causing harm."

This design, the launcher and the policy are public at
[yougame-co/yougame-sandbox](https://github.com/yougame-co/yougame-sandbox), so anyone can check
and attack them. After changing any of them, republish with `scripts/publish-oss.sh sandbox`.

This is the plan for that and the record of what phase 1 built and measured. Containment replaces
trust: a remix, a ROM hack or a community build will not carry a code signature, so what it can
reach has to be limited by the operating system instead.

## What runs today, and with what rights

| What                                                             | Where it runs                                                                                                                                      | Rights before this work                                                    |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Browser games                                                    | Chromium's sandboxed renderer (`src/renderer-config.ts`)                                                                                           | Already contained                                                          |
| Cartridge systems on Windows (NES … N64)                         | `yougame-libretro.exe` (`native/libretro/host.cpp`), a child window of the app                                                                     | Full user rights, the app's whole environment                              |
| RetroArch, Dolphin, DuckStation, PCSX2, PPSSPP, Flycast, melonDS | Separate programs from a pinned catalog (removed in desktop 0.11.0: emulators only run in the window now)                                          | Full user rights, the app's whole environment                              |
| Native builds                                                    | `src/native.ts`, staff-only, Authenticode/Gatekeeper required (Windows: every build sandboxed since 0.12.19, open to every creator; phase 5 below) | Full user rights, minimal environment (Windows since 0.12.19: the sandbox) |

The emulators parse untrusted input: ROMs, ROM hacks, patches and disc images that players upload
or pick. An emulator core is a large C/C++ program written for speed, with dynamic recompilers and
hand-rolled file parsers; a crafted ROM that corrupts its memory runs code with whatever rights the
emulator has.

## Threat model

The attacker controls a game: a ROM or patch uploaded as a remix, a disc image, or (later) a
native build. Assume it gets arbitrary code execution inside the process that runs it. Without a
sandbox that process is the player, so it could:

- **Read the player's files**: documents, browser profiles, the YouGame app's own cookie jar
  (`%APPDATA%\yougame-desktop\Network\Cookies`, i.e. the YouGame session), SSH keys, password-manager
  exports, cloud-sync folders.
- **Write or encrypt the player's files** (ransomware), or plant files elsewhere.
- **Persist**: a `Run` key under `HKCU`, a shortcut in the Startup folder, a scheduled task, a
  modified program in the app's own folder (the host, a core) that runs at the next launch.
- **Reach the network**: exfiltrate what it read, download a second stage, attack the LAN
  (router admin pages, NAS, printers) and loopback services (the app's own native SDK bridge,
  developer servers).
- **Spy**: key logging (low-level hooks, `GetAsyncKeyState`), clipboard reading, screen capture.
- **Start other programs** (`cmd`, `powershell`) that inherit all of the above.
- **Abuse the machine**: mine, fill memory, read other processes' memory.

Out of scope, now and in every phase: kernel and GPU-driver escapes (a sandboxed process still
talks to the GPU driver and to win32k), hardware attacks, and a player who turns the sandbox off.
The sandbox lowers the odds and the blast radius; it does not make a malicious game harmless.

## Target containment

### Windows: AppContainer + job object

- **One AppContainer profile per game copy** (`YouGame.Game.<sha256(save name)[:32]>`), so one
  game's saves are out of another game's reach. Created with `CreateAppContainerProfile` the first
  time, found again with `DeriveAppContainerSidFromAppContainerName`.
- **File grants by ACL**, nothing else readable: the AppContainer token passes an access check only
  where an ACE names its package SID, one of its capability SIDs, or ALL APPLICATION PACKAGES (system
  folders). The app adds:
  - read + execute for the shared named capability `yougameSandboxRuntime` on the program's folder
    (`resources\controllers`) and the cores folder, once (it checks for the ACE and leaves it);
  - read for the game's package SID on the game file;
  - read + write + delete for the game's package SID on its own saves and system folders.
- **Network by capability**: none for the emulator host (it never needs the network; the page does
  everything online). `internetClient` only for a program that needs to go online (native builds,
  phase 2), never `privateNetworkClientServer`. AppContainers cannot reach loopback at all without
  an administrator's exemption, which the app never asks for.
- **Job object**: `KILL_ON_JOB_CLOSE` (the program dies with the launcher, which the app kills when
  a game will not quit), no breakaway, one active process, `DIE_ON_UNHANDLED_EXCEPTION`, a memory
  limit (4 GB for the emulator), and UI limits that cost a game nothing: no clipboard read or write,
  no desktop switching, no display-settings changes, no system-parameter changes, no global atoms,
  no logoff.
- **Process attributes**: `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` (no child processes, enforced
  by the kernel, not just the job), an explicit inherited-handle list (stdin, stdout, stderr only),
  and mitigations: no extension points (AppInit DLLs, legacy hooks), no images from remote shares
  or with a low integrity label (so a DLL the game wrote cannot be loaded), no non-system fonts,
  bottom-up ASLR, terminate on heap corruption, System32 first when a DLL is found by name.
  Deliberately not set: dynamic-code prohibition (the N64 dynarec writes code), win32k lockdown
  (OpenGL needs it), Microsoft-signed-only images (cores are unsigned), `UILIMIT_HANDLES` (the
  window lives inside the app's).
- **A minimal environment**: the system's own variables, `TEMP`/`APPDATA`/`USERPROFILE` pointed into
  the container's own folder (`%LOCALAPPDATA%\Packages\<profile>\AC`), nothing of the app's.
- **Transport**: inherited pipes or handles only. Loopback HTTP (the native SDK bridge and the
  controller stream, `src/bridge.ts`) cannot cross the AppContainer boundary; phase 2 replaces it.

LPAC (less privileged AppContainer, no ALL APPLICATION PACKAGES) was tried and does not work for a
GL program: the GPU driver's files and keys are readable by ALL APPLICATION PACKAGES only, and
OpenGL falls back to Microsoft's GDI 1.1 renderer ("GL 3.x is not supported"). Granting the driver
to a capability would mean changing system ACLs as an administrator. Plain AppContainer it is.

### macOS: sandbox-exec profile (phase 4)

`sandbox-exec -f profile.sb` with an SBPL profile written per launch: `(deny default)`; read the
program, the core and the game file; read system libraries and frameworks
(`/System`, `/usr/lib`, `/Library/Frameworks` read-only); write only the game's saves folder;
`mach-lookup` for the window server, audio (`com.apple.audio.*`) and game controllers
(`com.apple.GameController`/IOHID) only; network outbound-only when the program needs it, never
`localhost`. Same pipe transport as Windows. `sandbox-exec` is deprecated but still what Chrome's
and Firefox's Mac sandboxes use underneath (`sandbox_init_with_parameters`); a signed helper with
the App Sandbox entitlement is the fallback if it ever goes away. Embedding on the Mac is by frame readback into a canvas, so there is no cross-process window
parenting to solve there.

## Phases

1. **Our libretro host on Windows** (this change). The emulators that run inside the window.
2. **Native builds**, plus a new transport for the native SDK bridge and the controller stream:
   a named pipe whose DACL grants the build's package SID (or an inherited anonymous pipe pair
   passed down by the launcher), replacing loopback HTTP; the SDK reads its handle from the
   environment. Grants: the build folder read + execute, a per-build data folder read + write,
   `internetClient`. The launcher already supports all of it (`--net internet`, `--env`).
3. **Third-party emulators** (RetroArch, Dolphin, DuckStation, PCSX2, PPSSPP, Flycast, melonDS)
   through the same launcher, each with its portable or user-folder switch so every write lands in
   a granted folder (Dolphin `-u <dir>`, PCSX2 `-portable`, DuckStation `portable.txt`, PPSSPP
   `--memstick`, RetroArch `--config`/`--appendconfig` with every `*_directory` set, melonDS and
   Flycast portable mode), a read grant on the player's disc image, `internetClient` only where
   netplay needs it, and the launcher's window adoption for Dolphin/PCSX2 reparenting. Each needs
   its own GPU-backend check (D3D11/12 and Vulkan; D3D is what UWP games use, so it is expected to
   work).
4. **Mac**: the sandbox-exec profile above, for the host (once the Mac embeds) and the catalog
   emulators.
5. **Only then** relax the signature requirement for builds that run sandboxed: unsigned remixes
   and community builds, with the consent dialog, hash checks and revocation unchanged.
   **Done for Windows native builds in desktop 0.12.19** (Luis, 2026-10-03: "Everything should be
   under our new sandbox paradigm"), ahead of phases 3 and 4: every Windows build runs in the
   sandbox (its launch spec or `DEFAULT_LAUNCH_SPEC`), none runs without it, no signature is
   checked, any game owner uploads them (keys included), and the site refuses Windows builds to
   older apps. Mac and Linux builds stay staff-only and signed until phase 4.
   **Online by default** (Luis, 2026-10-15): staff approval was removed. The sandbox cannot
   stop screen capture (below); the consent dialog still explains that risk. `games.native_internet`
   defaults to true; only explicit false means staff or automation turned online access off.
   `/api/native/builds/<id>` sends this as `internet` on every launch. A transfer preserves it.
   The build keeps the internet its spec (or the default spec) asks for (`native-launch.ts`
   `launchPlan`); `net: "none"` still means no internet. A blocked game runs offline and its stdio
   bridge limits it to `OFFLINE_SDK` (saves, reading and frame no-ops; no publishing, rooms or links).
   If the site cannot answer, the app still runs the build offline and explains the connection
   failure. Restoring online access after offline consent asks the player again. Only blocked
   games are withheld for a missing `YouGameNetGate/1` token, including staff-owned games;
   the existing sandbox version floor for non-staff builds remains. Desktop copy changes ship
   with the next desktop release; the sandbox and per-build `--net` behavior are unchanged.

## Phase 1 as built

- `native/sandbox/launcher.cpp` → `yougame-sandbox.exe`, a generic launcher next to the host
  (`resources\controllers`): profile, grants, capabilities, job, attributes, minimal environment,
  `CreateProcess` suspended → job → resume, wait, exit with the program's code (a program's own
  120 or 121 becomes 122). `120` means the sandbox could not be set up here (a grant, the job, the
  attributes) and `121` that this Windows cannot make an AppContainer at all; nothing ran in
  either case. `sandbox: running pid N in AppContainer …` on stderr, written before the program's
  first instruction, means it did. Both the launcher and the host link the C/C++ runtime
  statically (`/MT`): `dumpbin /dependents` lists only system DLLs (USERENV, ADVAPI32, KERNEL32,
  USER32, ole32 for the launcher; USER32, KERNEL32, GDI32, WINMM, IMM32, ole32, OLEAUT32,
  VERSION, ADVAPI32, SETUPAPI, SHELL32 for the host), so neither needs the VC++ redistributable.
- `src/sandbox-policy.ts` decides what to ask for (`embedSandbox`, `sandboxArgs`,
  `sandboxDecision`, `launcherEnv`), pinned by `tests/sandbox-policy.test.cjs`.
- `src/emulator.ts` `embed()` runs the host through the launcher. Each game copy now has its own
  folders, `emulator/saves/<name>/` and `emulator/system/<name>/` (saves an older version kept flat
  in `emulator/saves/` move in on first use; RetroArch launches use the same per-game folder), and
  a sandboxed run takes its core from the app's own `emulator/cores` (copied there from a RetroArch
  install when that is where it was found).
- **Only the app decides**: the page's launch request has no field for it. The sandbox is off only
  when there is no launcher (not Windows, or not built), when `emulator/settings.json` says
  `"sandbox": false` (the app's own file; support switch), or when the app runs with
  `YOUGAME_SANDBOX=off`. A launch that never got the game started in the sandbox ends one of two
  ways (`sandboxOutcome`, decided after the pipes close, so the "running" line is never missed):
  when the sandbox cannot exist on this computer (121, the launcher could not be started, or it
  died before its "running" line with one of the loader's failures: 0xC0000135 for a missing DLL,
  0xC0000139, 0xC000007B or 0xC0000142; any other early death, a crash included, is refused) the app runs that one launch
  without it; when it could not be set up here (120, or the launcher was stopped first) the app
  refuses and the page shows "The game's sandbox could not be set up on this computer, so it was
  not started." It never runs every game unsandboxed because a grant failed. Every unsandboxed
  run is logged as `[libretro <slug>] running WITHOUT the sandbox: <reason>`. Both paths were
  exercised by putting a launcher stand-in that fails to load (0xC0000135) and one that exits 120
  in place of `yougame-sandbox.exe` under the real shell: the first ran the game unsandboxed with
  that log line, the second showed the error within 3 seconds.
- Untrusted output and files: the host is now the untrusted side of its pipe, so the app caps an
  unterminated line at 64 KB, error text at 300 characters and event lines at 120, reads a save
  only if it is a plain file (not a link, one hard link) through one handle and never more than
  32 MB, writes the account's copy to a fresh temporary file (never through one the game left),
  refuses a saves folder that is a link, and moves old saves in by copy (a rename would keep the
  old ACL, which the game's AppContainer cannot open). A core in use by another game is left as
  it is; a new one goes in whole (copy, then rename).
- The core's folder (`emulator/system/<name>`) is per game too. Nothing populated the old shared
  `emulator/system` (the app fetches no BIOS); if a core ever needs shared system files, they get
  a read-only runtime grant.

### Prototype findings (Windows 11 26200, RTX 2080 on NVIDIA 595.95, SDL 3.4.16, Electron 44.4.5)

| Question                                                                       | Answer                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Evidence                                                                                                           |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Can the AppContainer process make its window a `WS_CHILD` of the app's window? | **No, not by itself**: `SetParent` from low integrity to a medium-integrity window fails with `ERROR_ACCESS_DENIED` (UIPI). **Yes from outside**: the launcher, at the app's integrity level, finds the host's window (class `SDL_app`, caption `yougame-libretro`) and reparents it; the host waits for that (polling `GetParent` while pumping messages) before it shows anything.                                                                           | `electron-embed.mjs`: child of the shell's window at the page's exact rectangle, follows a resize, gone after stop |
| Input focus and keyboard across the boundary                                   | Works: the page's `focus` command, then a real Escape key press, comes back from the host as `key escape`                                                                                                                                                                                                                                                                                                                                                      | `electron-embed.mjs` keyboard step                                                                                 |
| Resize/move after adoption                                                     | Works: the host's own `SetWindowPos` on its now-child window                                                                                                                                                                                                                                                                                                                                                                                                   | `electron-embed.mjs` resize step                                                                                   |
| OpenGL / hardware rendering for GLideN64                                       | Works: NVIDIA's ICD loads, GL 4.6 core context, mupen64plus_next's dynarec runs (no dynamic-code mitigation is set). A commercial N64 game renders identically in and out of the sandbox                                                                                                                                                                                                                                                                       | `libretro-host.mjs --sandbox` frame read back; 3D scene captured; peak memory ~0.9 GB                              |
| Strict handle checks                                                           | Windows enables them permanently in every AppContainer. NVIDIA's GL driver has a worker thread that closes a bad handle at startup about one run in eight, which then raises `STATUS_INVALID_HANDLE` and killed the host. The host now continues that exception only when the stack runs through a GPU driver (a module under `System32\DriverStore`); any other is still fatal. 0 failures in 24 runs after, 1 to 3 in 12 before; 0 in 12 outside the sandbox | `crash:` stack lines in the host's log                                                                             |
| Audio (SDL3 / WASAPI)                                                          | Works with no capability: the default device opens at the core's rate                                                                                                                                                                                                                                                                                                                                                                                          | host log `audio: Speaker/Headphone (Realtek(R) Audio)`                                                             |
| Controllers                                                                    | SDL's HIDAPI and raw-input backends cannot open HID devices from an AppContainer (0 pads). **Windows.Gaming.Input works** (it is brokered by the system): with `SDL_JOYSTICK_WGI=1` a DualSense is found and its sticks report live values while the app's window, not the host's, is in front                                                                                                                                                                 | host log `pad: PS5 Controller`; stick values in the trace                                                          |
| Saves                                                                          | Written only into the granted folders; a save the app wrote before launch is still overwritable by the host; files the host wrote are readable and rewritable by the app                                                                                                                                                                                                                                                                                       | `sandbox-containment.mjs`, `electron-embed.mjs` save step                                                          |
| LPAC                                                                           | Breaks OpenGL (GDI fallback); not used                                                                                                                                                                                                                                                                                                                                                                                                                         | host log `GL 3.x is not supported`                                                                                 |

Not exercised: button presses on a physical pad (only live stick values were seen), Xbox pads
through WGI (none attached; WGI is their native API), the GameCube adapter (the host never read it;
the controller helper does, outside the sandbox), AMD and Intel GPU drivers.

### Containment (`node tests/sandbox-containment.mjs`)

`sandbox-probe.exe` (tests only, never shipped) runs through the launcher with the emulator's exact
grants, inside a copy of the app's folder layout, and tries what malware would. The same probe runs
outside the sandbox on everything marked "outside: allowed", so each denial is the sandbox's doing.

| Attempt                                                                            | In the sandbox                       | Outside |
| ---------------------------------------------------------------------------------- | ------------------------------------ | ------- |
| Token                                                                              | AppContainer, low integrity (0x1000) |         |
| Read the game file, read the core                                                  | allowed                              |         |
| Write its own saves and system folders; overwrite a save the app wrote             | allowed                              |         |
| Read or write another game's saves                                                 | denied (5)                           | allowed |
| Read the app's cookie jar, a private key next to it                                | denied (5)                           | allowed |
| List the user profile, Documents; read `NTUSER.DAT`                                | denied (5)                           | allowed |
| Drop an `.exe` next to the app's data; overwrite a core, the host, the game file   | denied (5)                           | allowed |
| Write to the Startup folder; write an `HKCU\…\Run` value                           | denied (5)                           |         |
| Connect to a loopback server; to the same server on the LAN address                | denied (timeout)                     | allowed |
| Connect to the internet (1.1.1.1:443)                                              | denied (10013)                       |         |
| Resolve a name that exists (one.one.one.one)                                       | denied (no such name; nothing on the wire) | allowed |
| Start `cmd.exe`                                                                    | denied (367, child process blocked)  | allowed |
| Read the clipboard                                                                 | denied (5)                           |         |
| Open the app's process for reading                                                 | denied (5)                           | allowed |
| Commit 6 GB of memory                                                              | stopped at ~4 GB (job limit)         | allowed |
| Keys typed elsewhere (low-level hook and `GetAsyncKeyState`, while F13 is pressed) | 0 seen                               | 12 seen |
| Kill the launcher                                                                  | the sandboxed program dies with it   |         |
| Capture the screen through GDI                                                     | **allowed** (known gap, below)       |         |

### Known gaps and residual risk

- **Screen capture**: GDI `BitBlt` of the desktop works from an AppContainer on the same desktop.
  Running the host on a separate desktop would block it and break the embedding. The emulators get
  no network, so the only way out for what they capture is a save file, which the page uploads to
  the player's own account (private to them). A native build gets `internetClient`, and the SDK
  requests that publish data, by default unless its game is blocked (phase 5 above). An online
  build can capture and send the player's screen. This is a known, accepted risk (Luis, 2026-10-15);
  the consent dialog tells the player it can see the screen. Name resolution is not a way out either (measured 2026-10-09 with `pktmon` on port
  53): without `internetClient`, Windows answers "no such name" for a name that exists and sends
  nothing, while the same lookup outside the sandbox resolves and shows on the wire.
- **Drawing over the app**: a compromised host owns a child window of the app's window and can
  resize it over the whole client area, so it can draw a convincing fake page and read what is
  typed into it while it has focus. Without the internet it cannot send the result anywhere but
  its saves; an online game could. Online access is enabled by default unless blocked.
- **Disk**: the job limits memory, not disk; a compromised host can fill the disk inside its own
  folders.
- **Kernel, win32k, GPU driver, WGI and audio services** stay reachable; an exploit for any of them
  escapes. AppContainer is the same boundary UWP apps and Chromium's sandboxed utilities rely on.
- **Profiles accumulate**: one `%LOCALAPPDATA%\Packages\YouGame.Game.*` folder and registry mapping
  per game played. Small; a future cleanup can `DeleteAppContainerProfile` for games not played in
  months.
- **Unsandboxed fallback**: a computer that cannot create AppContainers (older than Windows 10
  1607, or a policy that blocks it) runs the emulator unsandboxed, logged. No page or game can
  cause that: the page's request has no say, and the game cannot run before the launcher's
  "running" line exists.
- **Save names can collide** (security review): the save name (`web/src/lib/emulators.ts`
  `saveName`) joins a 12-character hash prefix with patch slugs and cuts it at 120 characters,
  so two different patch lists can produce the same name, and with it the same profile and
  folders. A remix crafted that way could reach another remix's local saves. Fixing it changes
  every save's name (a migration of local and account saves), so it is the first item of phase 2:
  key the profile and folders by a hash of the full identity (dump hash + ordered patch ids).
- **Sandbox-written saves are read unsandboxed elsewhere**: RetroArch launches (Mac, Linux, or
  Windows without the host), the fallback above, and other computers through account sync parse
  a save state the sandboxed game wrote, with full rights. The ROM itself is already
  attacker-controlled on those paths, so this widens which parser is exposed rather than adding a
  capability; phases 3 and 4 close it.
- **A stalled host can freeze the app's window**: a child window across processes shares its
  parent's input queue, so a host that stops pumping messages holds the app's UI. The host's own
  watchdog (10 s without a frame) and the app's kill on stop bound it.

## Orca

Built on a branch, waiting for Luis (plan: `notes/lead-records/orca-sandbox/plan.md` in the
brawl-dolphin repo). Only an Orca that says it has a sandbox mode is jailed or put on the stdio
bridge: its manifest or `orca.json` says `"sandbox": 1`, or its own `Sys/Orca/features.json` does
(read from the install the app has already checked, so a manifest that lost the field marks nothing
by mistake). Any other Orca runs as before, on the loopback bridge, now behind the same request
allowlist. `src/orca-sandbox.ts` makes the one decision; nothing from the page, Orca or the emulator
settings takes part in it.

- **Windows**: `yougame-sandbox.exe` runs Orca in the `YouGame.Orca` AppContainer and a 6 GB job.
  Grants: its program folder (read + execute) and `orca/files` (read), made with `--grant-only`
  when it is installed or staged (a Play waits for one still under way); the disc file (never its
  folder; a file may sit on a drive root), the listing's run folder (read) and `orca/user-jailed`
  (write), at each launch. Network: `internetClient` and, by default,
  `privateNetworkClientServer` (the LAN; on a Public-profile network Windows allows it anyway),
  both by their fixed SIDs; no `internetClientServer` unless a switch adds it; never loopback.
  `--app-dlls` keeps Orca's own `d3dcompiler_47` (its shader cache misses otherwise); the other
  image-load rules stay, so a library Orca writes is never loaded. Orca opens a hidden window
  (`--embed-adopted`) at the app's rect, which the launcher makes a child of the app's with its own
  style (`--embed-keep-style`) and stops looking for after 60 s (`--embed-timeout-ms`). The backend
  is pinned to D3D11 inside. No SDL joystick backend runs inside (`SDL_JOYSTICK_WGI=0` too): its
  pads are the app's snapshots.
- **macOS**: `/usr/bin/sandbox-exec` with the deny-default profile in `src/orca-mac-sandbox.ts`,
  every path a realpath'd `-D` parameter, `TMPDIR` inside `orca/user-jailed`. The profile is
  chosen once per macOS build and Orca version by Orca's own probe (`Orca --sandbox-probe -u
  <empty folder>`, no disc; kept in `orca/sandbox-mac.json`): strict when the probe passes under
  it, relaxed (every service by name) only when strict fails it, a refusal when neither passes.
  A probe that does not answer in 30 s (macOS holds a new program's first launch while it scans
  it, minutes at times, and the probe is a new Orca's first launch) answers nothing: never relaxed
  for it, not kept, that run plays strict and the next Play asks again. Never by a player's run: one that ends before its first line is refused, not tried again
  relaxed, so a crafted disc or setting cannot pick the relaxed profile. The manifest may still
  choose a profile. The app reads Orca's memory (`footprint`) and stops it past 6 GB. Not on by
  default yet (`MAC_SANDBOX_ROLLED_OUT`): the support file or the manifest turns it on for
  testers. Known gaps: the window server's global key and idle state, UDP to IPv4-mapped loopback
  (`::ffff:127.0.0.1`), and Metal's own shader cache (`$(getconf DARWIN_USER_CACHE_DIR)co.yougame.orca`),
  which a jailed Orca writes and an unjailed one reads (to settle in M3's trace).
- **Jailed and unjailed runs never share a user folder.** Unjailed runs keep `orca/user`; jailed
  runs use `orca/user-jailed`, made at the first jailed Play from a copy of `orca/user` (folders
  and plain files only: no links, no caches or logs) and never copied back. So nothing a
  taken-over Orca plants in its folder (a Wii SD image, the NAND, `GameSettings`, `Config`, a shader
  cache) is ever parsed by an unjailed Orca, including the one that runs when a switch turns the
  jail off. Help > Reset Orca files deletes `orca/user-jailed`, the disc checks' and probes'
  leftover folders, the Mac's probe answers, and both AppContainers' own storage (the launcher's
  `--reset-profile`). The read entry on the player's disc file stays (it names only the Orca
  container).
- **The bridge**: on stdio (`YOUGAME_STDIO=1`), `yg {json}` lines (`src/orca-bridge.ts`). Orca may
  ask for `hello`, `mpTicket` (rebuilt field by field, always casual, 20 a minute) and `mpRoom`
  (rebuilt, 16 KB at most, newest wins), nothing else; what it reads back of a refusal is plain
  words, the details go to the log. Controller snapshots go down stdin, only the newest while Orca
  is not reading, and never one after a newer one. Orca's output lines are capped at 64 KB. A
  running Orca that says `orca alive` (about once a second, from its window's thread) and then not
  again for 10 s is stopped; only that line counts, and the computer's sleep never does. Linux
  stays on the loopback bridge (stdio has never run there).
- **The disc check** (`Orca --verify`) runs in its own `YouGame.OrcaVerify` profile with no
  network, a new empty folder for each check (`orca/verify-<random>`, deleted after it), its
  output lines capped, and no environment of the app's; a check whose launcher never said
  `running` counts for nothing.
- **On or off.** On Windows the jail waits for its rollout: `sandboxSwitch.windows.rollout: "on"`
  in the manifest, off by default, so nothing turns it on by lapsing. Once a computer has seen it
  on (from the current channel's manifest; an experimental build's rollout counts only while it
  is served) it stays on there (`orca/sandbox-state.json`), and only an emergency switch turns it
  off: the manifest's `windows.mode: "off"` (for at most 14 days, renewed by hand) or
  `userData/orca/sandbox.json` on one computer (`mode` on or off, `lan`, `inbound`, for at most 7
  days). The manifest's `lan` and `inbound` lapse with the same date as its off switch. A Play
  that cannot read the manifest decides as the last one did. **Never an automatic run without the
  jail**: a run the jail refused does not start and says one `[sandbox_*]` sentence with what to
  do (`sandbox_unsupported`: reinstall, or let `yougame-sandbox.exe` run in the antivirus;
  `sandbox_disc`: copy the disc into a folder of the player's own; `sandbox_denied`: Reset Orca
  files; `sandbox_embed`: try again, then restart YouGame). Start and crash reports carry
  `sandbox` on or off and the peak memory, and the page hears `orca sandbox on <os>` or
  `orca sandbox off <rollout|manifest|support|dev|system|legacy>` every run.

**What a taken-over Orca can still do** (the jail keeps it from the player's files, other programs,
loopback and the clipboard; these it does not):

- **Draw anywhere in the app's window, and on top of everything.** Its window is a child of the
  app's and can be resized over the whole client area, so it can draw a convincing fake page; and
  it can show a topmost window of its own anywhere on screen (containment probe `topmost`: shown,
  2026-10-10), a fake prompt over any app.
- **Read other windows' titles** (probe `wintitle`: a decoy window's title another process held was
  read from inside, 2026-10-10). A browser's title is its tab's page title, so this can show what
  the player has open. The job's `--ui-handles` (JOB_OBJECT_UILIMIT_HANDLES) may close it, but it
  also cuts Orca off from the app's window it is adopted into; it is untried with the real Orca
  (the W6 runs), as is `--lpac`.
- Not tested yet, because those probes need Luis's yes: reading keys typed into the app's window
  while Orca's is adopted (it shares the app window's input queue), and opening things through
  Windows (`ms-settings:`, web links, COM).
- **Act through the page with its status lines.** The app forwards Orca's `orca …` lines to the
  page, which acts on some of them as the player's own: `orca menu` and `orca queue` (start a
  ranked or casual search, ready up, skip an opponent, cancel), `orca controls` (save the name
  tag's controls), `orca stats` (network telemetry). So a taken-over Orca can search ranked as the
  player and throw the set, record skips, change the saved controls, and post made-up telemetry;
  through `mpRoom` it can name any profile id in the lobby it shows. None of it reaches money,
  passwords or other accounts. Limiting `queue ready` and `skip` while jailed, or asking for the
  player's own click before a ranked search, is page work for later.
- **Use the LAN** (by default) and, on a Public-profile network, Windows lets it reach the LAN
  anyway: routers, NAS boxes, printers. And on a FAT32 or exFAT drive, which keeps no
  permissions, the AppContainer check likely does not apply: every file on such a USB stick or SD
  card is probably open to it (not verified; a decoy probe is the next containment step).
- **Hang the app's window**, until the watchdog stops it (10 s without `orca alive`).

## Tests

In the desktop app's repository (the public mirror's README has the steps that work there):

```bash
cd desktop
npm run build && npm run native:build
node --test tests/sandbox-policy.test.cjs                          # policy, any OS
node --test tests/orca-sandbox.test.cjs tests/orca-bridge.test.cjs tests/orca-mac-sandbox.test.cjs tests/sandbox-launcher.test.cjs tests/orca-user.test.cjs tests/orca-sandbox-fields.test.cjs
node tests/orca-sandbox-containment.mjs                             # Windows, desktop session: Orca's grants, decoys, no keyboard probe
node tests/orca-mac-containment.mjs                                 # macOS: Orca's profile, decoys
node tests/sandbox-containment.mjs                                  # Windows: what the sandbox stops
node tests/libretro-host.mjs <core.dll> <rom> 8 --sandbox           # host alone, sandboxed, frame read back
node tests/electron-embed.mjs <mupen64plus_next_libretro.dll> <rom> # real shell: sandboxed, embedded, drawn, keyboard, save
YOUGAME_SANDBOX=off node tests/electron-embed.mjs …                 # the same unsandboxed, for comparison
```
