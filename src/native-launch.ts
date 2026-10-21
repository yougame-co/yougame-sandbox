// How the app starts a native build that ships a launch spec (docs/MELEE_UNLOCKED.md), as pure
// functions for tests/native-launch.test.cjs. A build zip may carry `yougame-native.json` beside
// its program:
//
//   {
//     "version": 1,
//     "args": ["--iso", "{disc}", "--settings-path", "{data}/settings.ini", "--sys-dir", "{build}/Sys"],
//     "disc": true,                                         // plays on the listing's base-game disc
//     "embed": { "class": "MeleePortWindow", "title": "Melee Unlocked" },   // drawn in the player box
//     "controllers": "mirror",                              // reads pads from the app (no USB of its own)
//     "net": "internet",                                    // outbound internet (online play), if YouGame approved the game; none without it
//     "memoryMb": 6144                                      // the sandbox's memory limit
//   }
//
// The app fills the placeholders with paths it chose ({build}: the unpacked build, read-only;
// {data}: the game's own folder, kept across updates; {disc}: the player's disc, read-only), so a
// build never names a path itself. Every Windows build runs inside the sandbox (sandbox-policy.ts),
// one without a spec under DEFAULT_LAUNCH_SPEC, and talks to the app over its stdin and stdout
// (bridge.ts StdioBridge), since a sandboxed process cannot reach the loopback bridge.
import path from "node:path";
import { sandboxProfile, type SandboxSpec } from "./sandbox-policy";

export const LAUNCH_SPEC_FILE = "yougame-native.json";

/**
 * How the sandbox runs a Windows build that ships no spec: no arguments, its own window, started in
 * its own folder (so assets it opens by relative path are found; that folder stays read-only, its
 * data folder is its writable place), asking for the internet (most games go online) but nothing
 * else outside its folders, no disc and no pads from the app (XInput still works inside the
 * sandbox), 8 GB. Asking is not getting: launchPlan grants the internet only to an approved game.
 */
export const DEFAULT_LAUNCH_SPEC: LaunchSpec = { args: [], disc: false, embed: null, controllers: "none", net: "internet", memoryMb: 8192, cwd: "build" };

export const SANDBOX_REQUIRED_MESSAGE = "This game runs only inside the YouGame sandbox, which this computer cannot set up.";

/**
 * How a build is launched (Luis, 2026-10-03: "Everything should be under our new sandbox paradigm").
 * Every Windows build runs in the sandbox, signed or not, under its own spec or the default one,
 * and none runs without it: a computer that cannot sandbox refuses (`testing`, the dev smoke test
 * with YOUGAME_SANDBOX=off, aside). macOS and Linux have no sandbox yet, so a build there needs the
 * operating system's verdict on its signature (`checkTrust`) and keeps its spec, if any, unsandboxed.
 *
 * `internet`: whether the site approved this game to go online (api/native/builds/<id> `internet`,
 * games.native_internet; Luis, 2026-10-09). The sandbox cannot stop a program from capturing the
 * screen (docs/DESKTOP_SANDBOX.md), so a build that also reaches the internet could send out what
 * is on it: a sandboxed build keeps the internet its spec asks for only when approved, and runs
 * offline otherwise. Unknown (the site not answering) counts as not approved.
 */
export function launchPlan(o: { platform: string; sandboxed: boolean; testing: boolean; spec: LaunchSpec | null; internet?: boolean }):
  | { held: boolean; checkTrust: boolean; spec: LaunchSpec | null }
  | { error: string } {
  if (o.platform === "windows") {
    if (o.sandboxed) {
      const spec = o.spec ?? DEFAULT_LAUNCH_SPEC;
      return { held: true, checkTrust: false, spec: o.internet === true || spec.net === "none" ? spec : { ...spec, net: "none" } };
    }
    if (!o.testing) return { error: SANDBOX_REQUIRED_MESSAGE };
    return { held: false, checkTrust: false, spec: o.spec };
  }
  return { held: false, checkTrust: !o.testing, spec: o.spec };
}

export type LaunchSpec = {
  args: string[];
  disc: boolean;
  embed: { cls: string; title: string } | null;
  controllers: "mirror" | "none";
  net: "internet" | "none";
  memoryMb: number;
  /** The working directory: the data folder (every spec file), or the build's own folder (DEFAULT_LAUNCH_SPEC). */
  cwd?: "data" | "build";
};

const PLACEHOLDER = /\{([a-z]+)\}/g;
const KNOWN = new Set(["build", "data", "disc"]);
const WINDOW_NAME = /^[A-Za-z0-9 ._-]{1,64}$/;

/** The spec in a build's file, or an error naming what is wrong. Strict: an unknown field or placeholder is refused, not ignored. */
export function parseLaunchSpec(text: string): { spec: LaunchSpec } | { error: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: `${LAUNCH_SPEC_FILE} is not JSON` };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: `${LAUNCH_SPEC_FILE} must be an object` };
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!["version", "args", "disc", "embed", "controllers", "net", "memoryMb"].includes(k)) return { error: `unknown field "${k}"` };
  if (o.version !== 1) return { error: "version must be 1" };
  const args = o.args ?? [];
  if (!Array.isArray(args) || args.length > 64 || !args.every((a) => typeof a === "string" && a.length <= 1024 && !/[\0\r\n]/.test(a)))
    return { error: "args must be at most 64 strings of at most 1024 characters" };
  for (const a of args as string[]) {
    for (const m of a.matchAll(PLACEHOLDER)) if (!KNOWN.has(m[1])) return { error: `unknown placeholder {${m[1]}}` };
    if (a.replace(PLACEHOLDER, "").includes("{")) return { error: `stray "{" in "${a}"` };
  }
  const disc = o.disc === true;
  if (o.disc !== undefined && typeof o.disc !== "boolean") return { error: "disc must be true or false" };
  if (!disc && (args as string[]).some((a) => a.includes("{disc}"))) return { error: "{disc} needs \"disc\": true" };
  let embed: LaunchSpec["embed"] = null;
  if (o.embed !== undefined) {
    const e = o.embed as Record<string, unknown>;
    if (!e || typeof e !== "object" || typeof e.class !== "string" || typeof e.title !== "string" || !WINDOW_NAME.test(e.class) || !WINDOW_NAME.test(e.title))
      return { error: "embed needs a window class and title (letters, digits, space . _ -)" };
    embed = { cls: e.class, title: e.title };
  }
  if (o.controllers !== undefined && o.controllers !== "mirror" && o.controllers !== "none") return { error: 'controllers must be "mirror" or "none"' };
  if (o.net !== undefined && o.net !== "internet" && o.net !== "none") return { error: 'net must be "internet" or "none"' };
  const memoryMb = o.memoryMb === undefined ? 4096 : o.memoryMb;
  if (typeof memoryMb !== "number" || !Number.isInteger(memoryMb) || memoryMb < 512 || memoryMb > 16384) return { error: "memoryMb must be a whole number from 512 to 16384" };
  return { spec: { args: args as string[], disc, embed, controllers: o.controllers === "mirror" ? "mirror" : "none", net: o.net === "internet" ? "internet" : "none", memoryMb } };
}

/**
 * The program's arguments with the app's paths in place of the placeholders. A placeholder followed
 * by "/sub/path" names a file inside that folder; the slashes become `sep` (backslashes on Windows).
 */
export function launchArgs(spec: LaunchSpec, paths: { build: string; data: string; disc: string | null }, sep: string = path.sep): string[] {
  if (spec.disc && !paths.disc) throw new Error("this game plays on your own disc: pick it first");
  return spec.args.map((a) => {
    if (!a.includes("{")) return a;
    const tail = sep === "/" ? (t: string) => t : (t: string) => t.replace(/\//g, sep);
    return a.replace(/\{([a-z]+)\}([^{]*)/g, (_, k: string, rest: string) => (k === "build" ? paths.build : k === "data" ? paths.data : (paths.disc as string)) + tail(rest));
  });
}

/** The game's folder: one per listing, so settings, saves and replays outlive a build update. */
export function nativeDataName(gameId: string): string {
  return gameId.replace(/[^A-Za-z0-9-]/g, "").slice(0, 64) || "game";
}

/**
 * The sandbox of a native build: its own folder read + execute, the disc read, its data folder its
 * only writable place (and its working directory, where a crash dump lands, unless the spec says
 * "build": DEFAULT_LAUNCH_SPEC),
 * outbound internet when it asks (online play), the window adopted into the player box when it draws there.
 * One profile per listing, shared by every build of it, like its data folder.
 */
export function nativeSandbox(o: { gameId: string; build: string; data: string; disc: string | null; spec: LaunchSpec; parent?: string; env: Record<string, string> }): SandboxSpec {
  return {
    profile: sandboxProfile(`native:${o.gameId}`),
    runtime: [],
    exec: [o.build],
    read: o.disc ? [o.disc] : [],
    write: [o.data],
    net: o.spec.net,
    maxMemoryMb: o.spec.memoryMb,
    cwd: o.spec.cwd === "build" ? o.build : o.data,
    env: o.env,
    ...(o.spec.embed && o.parent ? { embed: { parent: o.parent, cls: o.spec.embed.cls, title: o.spec.embed.title } } : {}),
  };
}
