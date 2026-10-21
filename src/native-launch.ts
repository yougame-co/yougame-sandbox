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
//     "net": "internet",                                    // outbound internet (online play), unless YouGame blocked the game or the app could not check;
//                                                           // "yougame": no network of its own, the app opens YouGame-only connections for it (docs/NATIVE_NET.md)
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
/** Shared by the app's UA and spec reader: old callers refuse the new field. */
export const DIRECT_UA_TOKEN = "YouGameDirect/1";
/** Steam base specs remain inert until an app explicitly advertises support. */
export const STEAM_BASE_UA_TOKEN = "YouGameSteamBase/1";

/**
 * How the sandbox runs a Windows build that ships no spec: no arguments, its own window, started in
 * its own folder (so assets it opens by relative path are found; that folder stays read-only, its
 * data folder is its writable place), asking for the internet (most games go online) but nothing
 * else outside its folders, no disc and no pads from the app (XInput still works inside the
 * sandbox), 8 GB. Asking is not getting: launchPlan grants the internet only when the site just
 * said the game goes online, so a blocked game, or one the site could not be asked about, runs offline.
 */
export const DEFAULT_LAUNCH_SPEC: LaunchSpec = { args: [], disc: false, base: null, embed: null, controllers: "none", net: "internet", memoryMb: 8192, cwd: "build" };

export const SANDBOX_REQUIRED_MESSAGE = "This game runs only inside the YouGame sandbox, which this computer cannot set up.";

/**
 * How a build is launched (Luis, 2026-10-03: "Everything should be under our new sandbox paradigm").
 * Every Windows build runs in the sandbox, signed or not, under its own spec or the default one,
 * and none runs without it: a computer that cannot sandbox refuses (`testing`, the dev smoke test
 * with YOUGAME_SANDBOX=off, aside). macOS and Linux have no sandbox yet, so a build there needs the
 * operating system's verdict on its signature (`checkTrust`) and keeps its spec, if any, unsandboxed.
 *
 * `internet`: whether the site says this game goes online (api/native/builds/<id> `internet`;
 * games.native_internet is a block switch, on unless YouGame blocked the game: Luis, 2026-10-15),
 * and false for a kept copy whose player chose Play offline (native.ts). The sandbox cannot stop a
 * program from capturing the screen (docs/DESKTOP_SANDBOX.md), so a build that also reaches the
 * internet could send out what is on it: a sandboxed build keeps the internet its spec asks for
 * only on an explicit true, and runs offline otherwise. Unknown (an older site, or the site not
 * answering) counts as offline. `net: "yougame"` follows the same rule: kept on an explicit true
 * (the sandbox still gets `--net none`, nativeSandbox; the app's broker opens its connections),
 * `"none"` otherwise.
 *
 * `branch`: the build is a test build of a crowd-loop branch (api/native/builds/<id> `branch`, or the
 * copy's record of it): a contributor's change nobody has merged, so it runs offline (net "none"),
 * whatever `internet` or the game's approval says (web/src/lib/native-branch.ts, compliance (c)).
 * That holds on every platform and for every `net`, "yougame" included: its spec comes back "none"
 * (no internetClient in the sandbox, and brokerMode gives it no broker), sandboxed or not.
 */
export function launchPlan(o: { platform: string; sandboxed: boolean; testing: boolean; spec: LaunchSpec | null; internet?: boolean; branch?: boolean }):
  | { held: boolean; checkTrust: boolean; spec: LaunchSpec | null }
  | { error: string } {
  // A test build's spec, wherever it runs: no network of its own and nothing for the broker.
  const own = o.spec && (o.branch === true || (o.spec.direct === true && !grantedInternet(o))) ? offlineSpec(o.spec) : o.spec;
  if (o.platform === "windows") {
    if (o.sandboxed) {
      const spec = o.spec ?? DEFAULT_LAUNCH_SPEC;
      return { held: true, checkTrust: false, spec: grantedInternet(o) || spec.net === "none" ? spec : offlineSpec(spec) };
    }
    if (!o.testing) return { error: SANDBOX_REQUIRED_MESSAGE };
    return { held: false, checkTrust: false, spec: own };
  }
  return { held: false, checkTrust: !o.testing, spec: own };
}

/** The same spec with no network: the disc, the box and the pads stay as it asked. */
function offlineSpec(spec: LaunchSpec): LaunchSpec {
  const { direct: _direct, ...rest } = spec;
  return { ...rest, net: "none" };
}

/**
 * Whether a build may have the internet (and with it the online SDK, bridge.ts OFFLINE_SDK): only
 * when the site approved its game just now, and never for a crowd-loop test build (`branch`). The
 * one rule launchPlan and the bridge both follow (native.ts), so the sandbox and the SDK agree.
 */
export function grantedInternet(o: { internet?: boolean; branch?: boolean }): boolean {
  return o.internet === true && o.branch !== true;
}

/** Whether a sandboxed build's stdio bridge gives it only the offline SDK (bridge.ts OFFLINE_SDK): whenever it may not have the internet. */
export function bridgeOffline(o: { sandboxed: boolean; internet?: boolean; branch?: boolean }): boolean {
  return o.sandboxed && !grantedInternet(o);
}

export type LaunchSpec = {
  args: string[];
  disc: boolean;
  base: { steam: number; buildids: string[]; files: string[]; name?: string; hashes?: Record<string, string[]> } | null;
  folders?: string[];
  /** Maximum simultaneous helper processes, in the same AppContainer and job. */
  children?: 1 | 2;
  embed: { cls: string; title: string } | null;
  controllers: "mirror" | "none";
  /** "yougame": the sandbox gives it no network, and the app opens YouGame-only connections for it (docs/NATIVE_NET.md). */
  net: "internet" | "yougame" | "none";
  direct?: true;
  memoryMb: number;
  /** The working directory: the data folder (every spec file), or the build's own folder (DEFAULT_LAUNCH_SPEC). */
  cwd?: "data" | "build";
};

const PLACEHOLDER = /\{([a-z]+)\}/g;
const KNOWN = new Set(["build", "data", "disc", "base"]);
const WINDOW_NAME = /^[A-Za-z0-9 ._-]{1,64}$/;

/** The spec in a build's file, or an error naming what is wrong. Strict: an unknown field or placeholder is refused, not ignored. */
export function parseLaunchSpec(text: string, userAgent = ""): { spec: LaunchSpec } | { error: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: `${LAUNCH_SPEC_FILE} is not JSON` };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { error: `${LAUNCH_SPEC_FILE} must be an object` };
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!["version", "args", "disc", "embed", "controllers", "net", "memoryMb", ...(userAgent.split(/\s+/).includes(DIRECT_UA_TOKEN) ? ["direct"] : []), ...(userAgent.split(/\s+/).includes(STEAM_BASE_UA_TOKEN) ? ["base", "folders", "children"] : [])].includes(k)) return { error: `unknown field "${k}"` };
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
  let base: LaunchSpec["base"] = null;
  if (o.base !== undefined) {
    const b = o.base as Record<string, unknown>;
    if (!b || typeof b !== "object" || Array.isArray(b) || Object.keys(b).some((k) => !["steam", "buildids", "files", "name", "hashes"].includes(k)))
      return { error: "base must be an object with steam, buildids and files" };
    if (typeof b.steam !== "number" || !Number.isInteger(b.steam) || b.steam < 1 || b.steam > 2147483647)
      return { error: "base.steam must be a whole app id from 1 to 2147483647" };
    const buildids = b.buildids === undefined ? [] : b.buildids;
    if (!Array.isArray(buildids) || buildids.length > 16 || !buildids.every((id) => typeof id === "string" && /^\d{1,12}$/.test(id)))
      return { error: "base.buildids must be at most 16 strings of 1 to 12 digits" };
    const files = b.files === undefined ? [] : b.files;
    if (!Array.isArray(files) || files.length > 32 || !files.every((file) => typeof file === "string" && file.length > 0 && file.length <= 260 && !file.includes("..") && !/[\\:\0-\x1f\x7f]/.test(file) && file.split("/").every((part) => part !== "" && part !== "." && part !== "..")))
      return { error: "base.files must be at most 32 safe relative paths using forward slashes, each at most 260 characters" };
    if (b.name !== undefined && (typeof b.name !== "string" || Array.from(b.name).length < 1 || Array.from(b.name).length > 80 || /[^\p{L}\p{M}\p{N}\p{P}\p{S} ]/u.test(b.name) || !b.name.trim()))
      return { error: "base.name must be 1 to 80 printable characters" };
    if (b.hashes !== undefined) {
      if (!b.hashes || typeof b.hashes !== "object" || Array.isArray(b.hashes) || !Object.entries(b.hashes).every(([file, hashes]) => files.includes(file) && Array.isArray(hashes) && hashes.length <= 16 && hashes.every((hash) => typeof hash === "string" && /^[a-f0-9]{64}$/i.test(hash))))
        return { error: "base.hashes must map base.files paths to at most 16 SHA-256 strings" };
    }
    base = { steam: b.steam, buildids, files, ...(b.name !== undefined ? { name: b.name as string } : {}), ...(b.hashes !== undefined ? { hashes: b.hashes as Record<string, string[]> } : {}) };
  }
  if (!base && (args as string[]).some((a) => a.includes("{base}"))) return { error: "{base} needs base" };
  if (o.folders !== undefined && (!Array.isArray(o.folders) || o.folders.length > 4 || !o.folders.every((folder) => typeof folder === "string" && /^(documents|localappdata)\/[A-Za-z0-9 ._-]{1,64}(\/[A-Za-z0-9 ._-]{1,64}){0,2}$/.test(folder) && folder.split("/").slice(1).every((part) => !part.includes("..") && part.trim() === part && !part.endsWith(".") && part !== "." && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(part)))))
    return { error: "folders must be at most 4 documents/ or localappdata/ paths with 1 to 3 plain segments" };
  if (o.children !== undefined && o.children !== 1 && o.children !== 2) return { error: "children must be an integer from 1 to 2" };
  if (o.children !== undefined && !base) return { error: "children needs base" };
  let embed: LaunchSpec["embed"] = null;
  if (o.embed !== undefined) {
    const e = o.embed as Record<string, unknown>;
    if (!e || typeof e !== "object" || typeof e.class !== "string" || typeof e.title !== "string" || !WINDOW_NAME.test(e.class) || !WINDOW_NAME.test(e.title))
      return { error: "embed needs a window class and title (letters, digits, space . _ -)" };
    embed = { cls: e.class, title: e.title };
  }
  if (o.controllers !== undefined && o.controllers !== "mirror" && o.controllers !== "none") return { error: 'controllers must be "mirror" or "none"' };
  if (o.net !== undefined && o.net !== "internet" && o.net !== "yougame" && o.net !== "none") return { error: 'net must be "none", "yougame" or "internet"' };
  if (o.direct !== undefined && o.direct !== true) return { error: "direct must be true" };
  if (o.direct === true && o.net !== "yougame") return { error: 'direct needs net "yougame"' };
  const memoryMb = o.memoryMb === undefined ? 4096 : o.memoryMb;
  if (typeof memoryMb !== "number" || !Number.isInteger(memoryMb) || memoryMb < 512 || memoryMb > 16384) return { error: "memoryMb must be a whole number from 512 to 16384" };
  return { spec: { args: args as string[], disc, base, ...(o.folders !== undefined ? { folders: o.folders as string[] } : {}), ...(o.children !== undefined ? { children: o.children as 1 | 2 } : {}), embed, controllers: o.controllers === "mirror" ? "mirror" : "none", net: o.net === "internet" || o.net === "yougame" ? o.net : "none", ...(o.direct === true ? { direct: true } : {}), memoryMb } };
}

/**
 * The program's arguments with the app's paths in place of the placeholders. A placeholder followed
 * by "/sub/path" names a file inside that folder; the slashes become `sep` (backslashes on Windows).
 */
export function launchArgs(spec: LaunchSpec, paths: { build: string; data: string; disc: string | null; base?: string | null }, sep: string = path.sep): string[] {
  if (spec.disc && !paths.disc) throw new Error("this game plays on your own disc: pick it first");
  if (spec.base && !paths.base) throw new Error("this game needs its Steam base: check it first");
  return spec.args.map((a) => {
    if (!a.includes("{")) return a;
    const tail = sep === "/" ? (t: string) => t : (t: string) => t.replace(/\//g, sep);
    return a.replace(/\{([a-z]+)\}([^{]*)/g, (_, k: string, rest: string) => (k === "build" ? paths.build : k === "data" ? paths.data : k === "base" ? (paths.base as string) : (paths.disc as string)) + tail(rest));
  });
}

/**
 * The game's folder: one per listing, so settings, saves and replays outlive a build update. A
 * crowd-loop test build (`testBuild`: its build id) gets one of its own beside it, so a player's
 * change nobody merged never reads or writes the player's own saves.
 */
export function nativeDataName(gameId: string, testBuild?: string | null): string {
  const game = gameId.replace(/[^A-Za-z0-9-]/g, "").slice(0, 64) || "game";
  const test = (testBuild ?? "").replace(/[^A-Za-z0-9]/g, "").slice(0, 12);
  return test ? `${game}-test-${test}` : game;
}

/**
 * The sandbox of a native build: its own folder read + execute, the disc read, its data folder its
 * only writable place (and its working directory, where a crash dump lands, unless the spec says
 * "build": DEFAULT_LAUNCH_SPEC),
 * outbound internet when it asks (online play), none for `net: "yougame"` (the app's broker opens its
 * connections, docs/NATIVE_NET.md), the window adopted into the player box when it draws there.
 * One profile per listing, shared by every build of it, like its data folder.
 */
export function nativeSandbox(o: { gameId: string; build: string; data: string; disc: string | null; spec: LaunchSpec; base?: string | null; folders?: string[]; parent?: string; env: Record<string, string> }): SandboxSpec {
  return {
    profile: sandboxProfile(`native:${o.gameId}`),
    runtime: [],
    exec: [o.build, ...(o.base ? [o.base] : [])],
    read: [...(o.disc ? [o.disc] : []), ...(o.base ? [o.base] : [])],
    write: [o.data, ...(o.folders ?? [])],
    net: sandboxNet(o.spec.net),
    maxMemoryMb: o.spec.memoryMb,
    ...(o.spec.children !== undefined ? { children: o.spec.children } : {}),
    cwd: o.spec.cwd === "build" ? o.build : o.data,
    env: o.env,
    ...(o.spec.embed && o.parent ? { embed: { parent: o.parent, cls: o.spec.embed.cls, title: o.spec.embed.title } } : {}),
  };
}

/** The launcher's network for a spec's `net`: only "internet" gets internetClient; "yougame" runs with none. */
export function sandboxNet(net: LaunchSpec["net"]): "internet" | "none" {
  return net === "internet" ? "internet" : "none";
}

/**
 * Whether a run gets the app's network broker, and in which mode (docs/NATIVE_NET.md): only a
 * build that may go online (grantedInternet: `internet`, as launchPlan's, and not a test build)
 * and whose spec, after launchPlan, asks for "yougame" or "internet". Offline, blocked and
 * `net: "none"` builds get none, and so does a crowd-loop test build (`branch`) whatever its spec
 * says, "yougame" included: `branch` is a field every caller has to fill in.
 */
export function brokerMode(spec: LaunchSpec, o: { internet: boolean; branch: boolean | undefined }): "yougame" | "internet" | null {
  if (!grantedInternet(o)) return null;
  return spec.net === "yougame" || spec.net === "internet" ? spec.net : null;
}

/**
 * Where a build's spec sits in its zip: beside its declared entry (readSpec in native.ts reads it
 * there once unpacked), as a zip name with `/`. Null when the site named no entry: the app picks one
 * only after unpacking (resolveEntry), so the spec's place is not known before.
 */
export function specZipName(entry: string | null): string | null {
  if (!entry) return null;
  const rel = entry.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!rel || rel.split("/").some((part) => part === ".." || part === "")) return null;
  const dir = path.posix.dirname(rel);
  return dir === "." ? LAUNCH_SPEC_FILE : `${dir}/${LAUNCH_SPEC_FILE}`;
}

/**
 * A spec held to a site or consent ceiling (none < yougame < internet). A player shown the
 * YouGame-only wording never gives a build the internet, whatever its unpacked spec asks:
 * "internet" runs as "yougame" (the app's broker, no network of its own). Undefined preserves
 * Phase A callers; Phase B launch always passes its freshly checked ceiling.
 */
export function grantedSpec(spec: LaunchSpec, grant: LaunchSpec["net"] | undefined): LaunchSpec {
  if (grant === "none") return offlineSpec(spec);
  return grant === "yougame" && spec.net === "internet" ? { ...spec, net: "yougame" } : spec;
}
