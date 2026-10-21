// How the app runs a game process inside the operating system's sandbox (docs/DESKTOP_SANDBOX.md),
// as pure functions so tests/sandbox-policy.test.cjs can pin them down: which AppContainer
// profile a game gets, what it may read and write, the launcher's command line, and when the
// app runs a game without the sandbox. Windows only so far: native/sandbox/launcher.cpp
// (yougame-sandbox.exe) does the AppContainer + job object work; this decides what to ask for.
import { createHash } from "node:crypto";
import { LAN_IN_JAIL } from "./jail-network";

/** yougame-sandbox's exit code when it could not set the sandbox up here (a grant, the job) and nothing ran. */
export const SANDBOX_SETUP_FAILED = 120;
/** yougame-sandbox's exit code when this Windows cannot make an AppContainer at all and nothing ran. */
export const SANDBOX_UNSUPPORTED = 121;
/** The required profile-specific home-network guard is missing; nothing ran. */
export const SANDBOX_NET_GUARD_MISSING = 123;
/** The line the launcher writes to stderr once the program runs inside the sandbox. */
export const SANDBOX_RUNNING = /^sandbox: running pid (\d+) in AppContainer (\S+)/m;
/** The line the launcher writes to stderr once the program is gone: its exit code (unsigned) and the job's peak memory. */
export const SANDBOX_EXIT = /^sandbox: exit (\d+), peak memory (\d+) MB\s*$/;

/**
 * The AppContainer profile of one game copy (its save name): one per game, so one game's saves
 * are out of another game's reach. Profile names allow [-_. A-Za-z0-9], at most 64 characters;
 * the save name is hashed so any valid name fits and none can collide with another's prefix.
 */
export function sandboxProfile(name: string): string {
  return `YouGame.Game.${createHash("sha256").update(name.toLowerCase()).digest("hex").slice(0, 32)}`;
}

export type SandboxSpec = {
  profile: string;
  /** The profile's display name (Windows shows it nowhere a player looks); "YouGame game" by default. */
  display?: string;
  /** Read + execute for every YouGame sandbox (the shared runtime capability): host program, cores. */
  runtime: string[];
  /** Read for this profile only. */
  read: string[];
  /** Read + execute for this profile only (a native build's own folder). */
  exec?: string[];
  /** Read + write + delete for this profile only. */
  write: string[];
  /**
   * Outbound internet (`internet`: internetClient), plus unsolicited inbound from the internet
   * (`internet-server`: internetClientServer). Never loopback.
   */
  net: "none" | "internet" | "internet-server";
  /** Reserved for a future LAN rollout; hard-disabled by LAN_IN_JAIL. */
  lan?: boolean;
  /** Orca mods only: require the installed home-network guard before any launch setup. */
  requireNetGuard?: boolean;
  /** Experimental USER handle limits; validate embedding on Windows before rollout. */
  uiHandles?: boolean;
  /** Test-only noninteractive window station/desktop. Incompatible with embedding. */
  isolatedUi?: boolean;
  /**
   * The program's own DLLs beside it rather than System32's copies (the launcher's --app-dlls: no
   * PREFER_SYSTEM32). Orca ships the d3dcompiler_47 its shader cache is keyed to and the CRT it was
   * built with; inside the sandbox it cannot write its own folder, so the mitigation guards nothing.
   */
  appDlls?: boolean;
  /** The job's memory limit for the process, in MB. */
  maxMemoryMb?: number;
  /** Native launch-spec opt-in only; Dolphin, packs and emulator cores never set this. */
  children?: 1 | 2;
  cwd?: string;
  /** Variables added to the program's environment (the launcher gives it only the system's own otherwise). */
  env?: Record<string, string>;
  /**
   * The app window (HWND, decimal) the program's window of class `cls` captioned `title` becomes a child of.
   * A sandboxed program may not do that itself (Windows refuses SetParent from low integrity
   * to a medium-integrity window), so the launcher does it from outside.
   */
  embed?: {
    parent: string;
    cls: string;
    title: string;
    keepStyle?: boolean;
    /** Stop looking for the window this long after the launch (Orca's comes within seconds, or never); without it, as long as the program runs (an emulator core's window comes after the game loaded). */
    timeoutMs?: number;
  };
};

/** yougame-sandbox's arguments for running `program` with `args` under `spec`. */
export function sandboxArgs(spec: SandboxSpec, program: string, args: string[]): string[] {
  const out = ["--profile", spec.profile, "--display", spec.display ?? "YouGame game", "--net", spec.net];
  out.push("--parent-pid", String(process.pid));
  if (LAN_IN_JAIL && spec.lan) out.push("--net-lan");
  if (spec.requireNetGuard) out.push("--require-net-guard");
  if (spec.uiHandles) out.push("--ui-handles");
  if (spec.isolatedUi) out.push("--isolated-ui");
  if (spec.appDlls) out.push("--app-dlls");
  out.push(...grantArgs(spec));
  if (spec.children !== undefined) {
    if (spec.children !== 1 && spec.children !== 2) throw new Error("children must be an integer from 1 to 2");
    out.push("--child-processes", String(spec.children));
  }
  if (spec.maxMemoryMb) out.push("--max-memory", String(spec.maxMemoryMb));
  if (spec.cwd) out.push("--cwd", spec.cwd);
  for (const [k, v] of Object.entries(spec.env ?? {})) out.push("--env", `${k}=${v}`);
  if (spec.embed) {
    out.push("--embed-parent", spec.embed.parent, "--embed-class", spec.embed.cls, "--embed-title", spec.embed.title);
    if (spec.embed.keepStyle) out.push("--embed-keep-style");
    if (spec.embed.timeoutMs) out.push("--embed-timeout-ms", String(spec.embed.timeoutMs));
  }
  return [...out, "--", program, ...args];
}

function grantArgs(spec: Pick<SandboxSpec, "runtime" | "read" | "exec" | "write">): string[] {
  const out: string[] = [];
  for (const p of spec.runtime) out.push("--runtime", p);
  for (const p of spec.read) out.push("--read", p);
  for (const p of spec.exec ?? []) out.push("--exec", p);
  for (const p of spec.write) out.push("--write", p);
  return out;
}

/**
 * yougame-sandbox's arguments for applying `spec`'s grants and nothing else (--grant-only): the app
 * grants Orca's program folder when it installs it, so the first Play does not walk ~2,800 files.
 */
export function grantOnlyArgs(spec: Pick<SandboxSpec, "profile" | "display" | "runtime" | "read" | "exec" | "write">): string[] {
  return ["--grant-only", "--profile", spec.profile, "--display", spec.display ?? "YouGame game", ...grantArgs(spec)];
}

/** yougame-sandbox's arguments for deleting a profile and its own storage (--reset-profile): Help > Reset Orca files. */
export function resetProfileArgs(profile: string): string[] {
  return ["--reset-profile", "--profile", profile];
}

/**
 * What the launcher said about a run, from its stderr lines (which the program shares): the
 * program's pid from the FIRST running line (written before the program's first instruction, so it
 * cannot be forged first) and the job's peak memory from the LAST exit line (written once the
 * program is gone, after anything it printed). `exitCode`: that line's code, which differs from
 * the launcher's own exit code only for a program that exited 120 or 121 (the launcher says 122).
 */
export type LauncherReport = {
  pid: number | null;
  exitCode: number | null;
  peakMb: number | null;
  /** Exact read-grant error 5 with the launcher's administrator-owned signature, before spawn. */
  adminReadGrantDenied?: string | null;
};

/** Reads the launcher's own lines as they come; feed it every complete stderr line. */
export class LauncherLines {
  pid: number | null = null;
  exitCode: number | null = null;
  peakMb: number | null = null;
  adminReadGrantDenied: string | null = null;
  /** The launcher's other lines (a grant it refused, a step that failed), the first few, for the log and the refusal. */
  readonly said: string[] = [];

  line(raw: string) {
    const line = raw.replace(/\r$/, "");
    if (!line.startsWith("sandbox: ")) return;
    const running = /^sandbox: running pid (\d+) in AppContainer /.exec(line);
    if (running) {
      if (this.pid === null) this.pid = Number(running[1]);
      return;
    }
    const exit = SANDBOX_EXIT.exec(line);
    if (exit) {
      this.exitCode = Number(exit[1]);
      this.peakMb = Number(exit[2]);
      return;
    }
    // Only before the program runs: after that, a "sandbox:" line may be the program's own.
    if (this.pid === null) {
      // Parse before clipping diagnostics: a long disc path must still match in full. No other
      // grant, ACL-read failure, error code, or child-written line qualifies for the P+ retry.
      const denied = /^sandbox: cannot grant read on (.+) \(error 5\); install-time capability RX grant is required for administrator-owned files$/.exec(line);
      if (denied && this.adminReadGrantDenied === null) this.adminReadGrantDenied = denied[1];
      if (this.said.length < 8) this.said.push(line.slice(0, 300));
    }
  }

  report(): LauncherReport {
    return { pid: this.pid, exitCode: this.exitCode, peakMb: this.peakMb, adminReadGrantDenied: this.adminReadGrantDenied };
  }
}

/**
 * The in-window emulator's sandbox: it loads the host and the core (runtime), reads the game
 * file (`rom`: a cartridge copy, or the player's disc image where it lies plus the track files a
 * .cue or .gdi names beside it; each file alone, never its folder), keeps its saves and the core's own files in the game's folders, and has no network at
 * all (the host never needs it; the page does everything online). 4 GB covers an N64 core with
 * a GPU driver loaded many times over and still stops a runaway allocation from paging the
 * machine to a halt.
 */
export function embedSandbox(o: { name: string; hostDir: string; coresDir: string; rom: string | string[]; saves: string; system: string; parent?: string; guards?: Record<string, string> }): SandboxSpec {
  return {
    profile: sandboxProfile(o.name),
    runtime: [o.hostDir, o.coresDir],
    read: Array.isArray(o.rom) ? [...o.rom] : [o.rom],
    write: [o.saves, o.system],
    net: "none",
    maxMemoryMb: 4096,
    cwd: o.saves,
    // Controllers: the sandbox cannot open HID devices, so SDL's HIDAPI and raw input backends see
    // nothing; Windows.Gaming.Input is brokered by the system and works inside an AppContainer.
    // An agent's copy: its SDL guards too (native-policy.ts agentSdlGuards).
    env: { SDL_JOYSTICK_WGI: "1", ...o.guards },
    // SDL3 registers its windows as "SDL_app" (SDL_windowsevents.c SDL_RegisterApp); host.cpp captions its own "yougame-libretro".
    ...(o.parent ? { embed: { parent: o.parent, cls: "SDL_app", title: "yougame-libretro" } } : {}),
  };
}

export type SandboxDecision = { sandboxed: true } | { sandboxed: false; reason: string };

/**
 * Whether a launch runs sandboxed. Only the app decides: the page's request has no say. Off
 * where there is no launcher (not Windows, or not built), when the player's settings file says
 * so (the app's own file in its user data folder, which no page can write), or when the app was
 * started with YOUGAME_SANDBOX=off for support. Every "false" is logged by the caller.
 */
export function sandboxDecision(o: { platform: string; launcher: string | null; setting?: unknown; env?: Record<string, string | undefined> }): SandboxDecision {
  if (o.platform !== "win32") return { sandboxed: false, reason: "no sandbox on this platform yet" };
  if (!o.launcher) return { sandboxed: false, reason: "yougame-sandbox.exe is missing" };
  if (o.env?.YOUGAME_SANDBOX === "off") return { sandboxed: false, reason: "YOUGAME_SANDBOX=off" };
  if (o.setting === false) return { sandboxed: false, reason: "the sandbox is switched off in the emulator settings" };
  return { sandboxed: true };
}

/**
 * What a sandboxed run that ended this way means (read stderr whole, after "close"):
 * - "ran": the launcher said "running", so the game ran inside the sandbox and its exit is its own.
 *   The launcher writes that line before the game's first instruction, so no game can avoid it.
 * - "unsupported": the sandbox cannot exist on this computer (Windows could not make the
 *   AppContainer, 121; or the launcher program itself could not load: a spawn error, or one of the
 *   loader's NTSTATUS exits in LOADER_FAILURES, such as 0xC0000135 for a missing DLL). The app runs
 *   the game once more without it and logs that. Any other NTSTATUS (a crash, an access violation)
 *   is "failed": a launcher that died some other way is not a reason to drop the sandbox.
 * - "failed": the launcher could not set the sandbox up here (120: a grant, the job, the
 *   attributes), or it was stopped before it got there. The app refuses the launch with a clear
 *   error rather than quietly running every game unsandboxed on such a computer.
 * The launcher maps a game's own exit code 120 or 121 to 122.
 */
/** The loader's own failures to start a program: missing DLL, missing entry point, wrong image, DLL init. */
export const LOADER_FAILURES: ReadonlySet<number> = new Set([0xc0000135, 0xc0000139, 0xc000007b, 0xc0000142]);

export function sandboxOutcome(exitCode: number | null, stderr: string, spawnFailed = false): "ran" | "unsupported" | "failed" {
  if (SANDBOX_RUNNING.test(stderr)) return "ran";
  if (spawnFailed || exitCode === SANDBOX_UNSUPPORTED) return "unsupported";
  if (exitCode !== null && LOADER_FAILURES.has(exitCode >>> 0)) return "unsupported";
  return "failed";
}

/** What the player reads when the sandbox could not be set up and the game was not started. */
export const SANDBOX_FAILED_MESSAGE = "The game's sandbox could not be set up on this computer, so it was not started. Try again, or restart the YouGame app.";

/**
 * The launcher's own environment: just what Windows needs to start a program. The launcher
 * builds the sandboxed program's environment itself from a short list, so none of the app's
 * variables (tokens, NODE_OPTIONS, ELECTRON_*) reach the game.
 */
export function launcherEnv(env: Record<string, string | undefined>): Record<string, string> {
  const keep = ["SystemRoot", "windir", "SystemDrive", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "NUMBER_OF_PROCESSORS", "OS", "PATHEXT", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "ProgramData", "ALLUSERSPROFILE"];
  const out: Record<string, string> = {};
  // Windows variable names are case-insensitive; Node keeps the case the parent used.
  const lower = new Map(Object.entries(env).map(([k, v]) => [k.toLowerCase(), v]));
  for (const k of keep) {
    const v = lower.get(k.toLowerCase());
    if (typeof v === "string" && v) out[k] = v;
  }
  const root = out.SystemRoot || "C:\\Windows";
  out.PATH = `${root}\\System32;${root}`;
  return out;
}
