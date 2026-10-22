# YouGame sandbox

The YouGame desktop app runs games that anyone can make: remixes, ROM hacks, mods, community
builds. None of them carry a code signature, so the app doesn't trust them. On Windows it runs them
inside an operating-system sandbox instead, so a malicious game can't reach the player's files,
accounts or computer. On macOS that's true for YG Dolphin on the public beta so far, and Linux isn't
there yet (see the table).

This repo is that sandbox, published so anyone can check it and try to break it. If you find a way
out, please report it privately: see
[SECURITY.md](https://github.com/yougame-co/.github/blob/main/SECURITY.md).

## What runs sandboxed

| What                                                          | Windows                                                   | macOS                                  | Linux                    |
| ------------------------------------------------------------- | --------------------------------------------------------- | -------------------------------------- | ------------------------ |
| Emulators in the app's window, incl. ROM hacks and disc games | Sandboxed, no network                                     | **Not yet** (planned: `sandbox-exec`)  | Not yet                  |
| Native game builds, from any creator                          | Sandboxed; online unless YouGame turned it off             | Staff-only and signed until then       | Staff-only               |
| YG Dolphin, our Dolphin fork, and the mods that run on it | Every mod is sandboxed (this launcher), with internet access. YG Dolphin without a mod: sandboxed on the public beta, next in the released app | Sandboxed on the public beta (`sandbox-exec`, deny by default; it can't block the home network). Not yet in the released app | Not yet |
| Browser games                                                 | Chromium's renderer sandbox                               | Chromium's renderer sandbox            | Chromium's renderer sandbox |

Mods built by other players will only run on other players' machines once YG Dolphin runs sandboxed on
both Windows and macOS. On the public beta it now does; the released app's macOS sandbox comes next. [docs/ORCA_MODS.md](docs/ORCA_MODS.md) explains why, and what else stands
between a mod and the player's computer.

## What it stops, and what it doesn't

[docs/DESKTOP_SANDBOX.md](docs/DESKTOP_SANDBOX.md) is the design and the record of what was
measured: the threat model, every grant, the containment test (what a compromised game tried and
whether the sandbox stopped it), and the known gaps.

In short, a sandboxed game can't read the player's files or the app's sign-in cookie, can't start
programs, can't persist across a restart, and can't use more than its memory cap. Emulators get no
network at all; a native build reaches the internet, and YouGame's own online features (scores,
replays, multiplayer), unless YouGame turned online access off for its game. The sandbox can't stop
an online build from capturing the screen and sending it: a known, accepted risk. A sandboxed game still talks to the GPU
driver and the OS kernel directly (Chromium puts the GPU behind a separate process; this sandbox
doesn't), so a driver or kernel bug is a way out.

## What's here

| Path                          | What it is                                                                                   |
| ----------------------------- | -------------------------------------------------------------------------------------------- |
| `native/sandbox/launcher.cpp` | `yougame-sandbox.exe`: starts one program inside an AppContainer and a job object              |
| `native/sandbox/network.hpp`  | The home-network guard: Windows Filtering Platform rules, installed once with the player's OK, that block one sandbox profile from private and local addresses (for mods). Not switched on yet |
| `native/sandbox/probe.cpp`    | A stand-in for a compromised game, for the containment test. Never shipped                   |
| `native/sandbox/steam-probe.c`, `test-fixtures/` | A stand-in game for the Steam helper opt-in test, and its fake Steam folder. Never shipped |
| `native/tests/`               | The launcher's own Windows tests (CTest): window adoption and the helper-process ceiling     |
| `src/sandbox-policy.ts`       | What the app asks the launcher for on each launch                                            |
| `src/native-launch.ts`        | How a native build is launched: its launch file, the default, and the internet approval     |
| `src/save-files.ts`           | The save files a game copy owns, which is what the sandbox lets an emulator write            |
| `tests/`                      | The policy tests (any OS) and the containment test (Windows)                                 |
| `docs/`                       | The design, the measurements, and the threat model for YG Dolphin mods                             |

The rest of the desktop app is private, including the emulator host that parses the ROM
(`native/libretro/host.cpp`), the code that starts YG Dolphin, and the bridge games talk to the app over.
The docs name those files for context. This repo mirrors the parts that decide what a game can
reach.

## Build and test

The policy tests, on any OS with Node 22 or later:

```bash
npm ci
npm test
```

The launcher and the containment test, on Windows with Visual Studio 2022 and CMake (on an ARM64
PC, use `-A ARM64` and `win32-arm64`):

```bash
npm ci && npm run build
cmake -S native/sandbox -B native/build-sandbox-x64 -A x64
cmake --build native/build-sandbox-x64 --config Release
cmake --install native/build-sandbox-x64 --config Release --prefix native/bin/win32-x64
node tests/sandbox-containment.mjs
node tests/native-net-containment.mjs
```

The Tests section at the end of the design doc lists the app's own end-to-end tests, which need
the rest of the app.

## How changes land

The desktop app's repository is the source of this code. YouGame republishes this mirror when any
of it changes, and each commit here says which monorepo commit it came from. Issues and pull
requests are welcome; accepted changes are ported into the app and come back with the next
publish.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE).
