# YG Dolphin mods: threat model

[YG Dolphin](https://github.com/yougame-co/orca-netplay) is YouGame's fork of the Dolphin emulator. It
runs Super Smash Bros. Brawl, Project+ and the mods built on them, with rollback netplay. Players
will be able to build and vote on mods together, with AI agents doing much of the building. That
means code from many people running on everyone's computer, so this page says what stands between
a mod and the player's machine. YG Dolphin's own engine is never built that way; only the games and mods
on top of it are.

## What a mod can contain

- **Data:** game files on the virtual SD card, menu text, rulesets, stage lists.
- **Guest code:** Gecko codes, assembly patches and a launcher `.dol`. These are PowerPC programs
  for the emulated Wii. Dolphin's JIT translates them into the computer's own code, but that code
  only sees the emulated Wii's memory and devices.
- **Textures:** PNG only.
- **Scripts (planned):** Luau, run in a sandboxed VM that can read and write emulated memory and
  nothing else: no files, no network, no clock, no host.

A mod never contains a program for the player's own operating system.

## Why guest code still matters

Guest code can't touch the computer directly, but it controls everything the emulated hardware
receives: graphics commands, Wii system calls (including the Wii's file service, which Dolphin turns into real files in
YG Dolphin's own folder), audio, disc and SD reads. Dolphin was written to be
accurate and fast, not to withstand hostile guest code. A memory-safety bug in how it handles any
of those inputs could let a crafted mod run its own code inside the YG Dolphin process. So the emulator
is a boundary, but not one to rely on alone.

## The layers

| Layer                                                        | What it does                                                                                                                                                                                         | Status                                              |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| What a mod can be                                            | Data, guest code, PNGs and (later) Luau only. Every field of a mod's manifest is validated; anything unknown refuses the session                                                                     | Designed, being built                               |
| Switches a mod can't touch | Cheats, graphics mods, Riivolution, SD writes and the determinism settings are forced by the engine, whatever the mod asks | In YG Dolphin today for every session; the mod manifest side is being built |
| Guest networking off                                         | The emulated Wii's sockets and SSL are refused                                                                                                                                                       | In YG Dolphin today                                       |
| PNG re-encoding                                              | Textures are decoded and re-encoded at publish, so YG Dolphin never parses an image a mod supplied                                                                                                         | Designed                                            |
| Luau VM                                                      | Scripts get emulated memory and nothing else                                                                                                                                                         | Designed                                            |
| Emulator features a mod doesn't need, off | Bluetooth passthrough, WiiLink, Skylanders, Infinity and microphone devices and EXI devices are off, so less of Dolphin is reachable | Mostly in YG Dolphin today; USB passthrough next |
| **OS sandbox around YG Dolphin**                                   | If a mod does break out of the emulator, it lands in a process that can't read the player's files, start programs or persist ([this repo](../README.md))                                             | **On the public beta for Windows and macOS. In the released app, on Windows for every mod. Linux not yet. The guarantee everything else rests on** |
| Checks before a build runs anywhere but its author's machine | Automated rules, a trace of which hardware and system calls the mod touches compared with the base game, and an agent review. The detection rules stay private; they are a filter, not the guarantee | Planned                                             |
| A kill switch per mod version                                | Pulling a bad version stops it everywhere within minutes                                                                                                                                             | Planned                                             |
| Fuzzing Dolphin                                              | Millions of hostile inputs aimed at the code a mod controls, with fixes sent to upstream Dolphin                                                                                                     | Planned                                             |
| Accountability                                               | Every submission is recorded under a contributor account; accounts that submit malicious mods are banned                                                                                             | Planned                                             |

**The rule until the sandbox ships:** a mod built by someone else runs only on its author's
machine until YG Dolphin runs inside the OS sandbox on both Windows and macOS.

Where that stands (October 2026): YG Dolphin runs inside the OS sandbox on Windows and macOS on the public beta,
so the rule is met there. The released app sandboxes every mod on Windows, and its macOS sandbox comes next.

## What stays open

- **The screen.** A program inside the Windows sandbox can still capture the screen; stopping that
  would break the game's window. YG Dolphin also needs the network (below). So a mod that broke out of
  the emulator could see your screen and send it out. The sandbox stops it reading your files,
  starting programs and staying on your computer, not this, which is why the emulator itself has
  to hold too (fuzzing, the features turned off).
- **Files in YG Dolphin's own folder.** Wii saves go through the Wii's file service, which writes real
  files in YG Dolphin's folder. A mod's guest code can write there as well; the sandbox keeps those
  writes inside that folder, and Dolphin's handling of the file service's paths is a fuzzing target.
- **The GPU driver and the OS kernel.** YG Dolphin has to draw, and every sandbox, browsers included,
  still talks to them. A driver or kernel bug is a way out, so an escape takes two bugs: one in
  Dolphin and one in the driver or kernel.
- **The network.** YG Dolphin needs it for matches and direct links between players. The sandbox keeps
  the player's files out of reach, but a compromised YG Dolphin could still use the player's connection.
- **What the player could do in that game.** YG Dolphin talks to the app over the same bridge a native
  game uses, so a compromised YG Dolphin could act as the player inside that game: write its saves,
  submit scores, queue for matches, invite friends. It never gets the player's YouGame sign-in,
  and buying anything still needs the player's click.

Found a hole in any of this? Please report it privately:
[SECURITY.md](https://github.com/yougame-co/.github/blob/main/SECURITY.md).
