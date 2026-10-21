const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  SANDBOX_SETUP_FAILED,
  SANDBOX_UNSUPPORTED,
  SANDBOX_FAILED_MESSAGE,
  sandboxProfile,
  sandboxArgs,
  embedSandbox,
  sandboxDecision,
  sandboxOutcome,
  launcherEnv,
} = require("../dist/sandbox-policy.js");
const { isSaveOf } = require("../dist/save-files.js");

test("one AppContainer profile per game copy, always a valid profile name", () => {
  const a = sandboxProfile("super-mario-64-usa");
  assert.match(a, /^YouGame\.Game\.[0-9a-f]{32}$/);
  assert.ok(a.length <= 64);
  assert.equal(sandboxProfile("super-mario-64-usa"), a, "stable across launches");
  // Windows paths are case-insensitive, so the save folder and the profile are too.
  assert.equal(sandboxProfile("Super-Mario-64-USA"), a);
  assert.notEqual(sandboxProfile("super-mario-64-usa-2"), a);
  assert.match(sandboxProfile("x".repeat(120)), /^YouGame\.Game\.[0-9a-f]{32}$/);
});

test("the emulator's grants: read the runtime and the game, write only its own folders, no network", () => {
  const spec = embedSandbox({
    name: "zelda",
    hostDir: "C:\\app\\resources\\controllers",
    coresDir: "C:\\u\\emulator\\cores",
    rom: "C:\\u\\emulator\\roms\\zelda.z64",
    saves: "C:\\u\\emulator\\saves\\zelda",
    system: "C:\\u\\emulator\\system\\zelda",
    parent: "1234",
  });
  assert.equal(spec.profile, sandboxProfile("zelda"));
  assert.deepEqual(spec.runtime, ["C:\\app\\resources\\controllers", "C:\\u\\emulator\\cores"]);
  assert.deepEqual(spec.read, ["C:\\u\\emulator\\roms\\zelda.z64"]);
  assert.deepEqual(spec.write, ["C:\\u\\emulator\\saves\\zelda", "C:\\u\\emulator\\system\\zelda"]);
  assert.equal(spec.net, "none");
  assert.ok(spec.maxMemoryMb >= 2048 && spec.maxMemoryMb <= 8192);
  assert.equal(spec.cwd, "C:\\u\\emulator\\saves\\zelda");
  assert.deepEqual(spec.env, { SDL_JOYSTICK_WGI: "1" });
  assert.deepEqual(spec.embed, { parent: "1234", cls: "SDL_app", title: "yougame-libretro" });
  // Without a parent window (the host test's top-level run) nothing is adopted.
  const top = embedSandbox({ name: "zelda", hostDir: "h", coresDir: "c", rom: "r", saves: "s", system: "y" });
  assert.equal(top.embed, undefined);
  // A disc: the player's image where it lies and the tracks its sheet names, each file alone.
  const disc = embedSandbox({ name: "melee", hostDir: "h", coresDir: "c", rom: ["D:\\Games\\Crash.cue", "D:\\Games\\Crash (Track 1).bin"], saves: "s", system: "y" });
  assert.deepEqual(disc.read, ["D:\\Games\\Crash.cue", "D:\\Games\\Crash (Track 1).bin"]);
  assert.deepEqual(disc.write, ["s", "y"]);
});

test("the launcher's command line carries every grant, then the program after --", () => {
  const spec = {
    profile: "YouGame.Game.abc",
    runtime: ["C:\\host", "C:\\cores"],
    read: ["C:\\rom.nes"],
    write: ["C:\\saves\\a"],
    net: "none",
    maxMemoryMb: 4096,
    cwd: "C:\\saves\\a",
    env: { SDL_JOYSTICK_WGI: "1" },
    embed: { parent: "42", cls: "SDL_app", title: "yougame-libretro" },
  };
  const args = sandboxArgs(spec, "C:\\host\\yougame-libretro.exe", ["core.dll", "--name", "a b"]);
  const dash = args.indexOf("--");
  assert.deepEqual(args.slice(dash), ["--", "C:\\host\\yougame-libretro.exe", "core.dll", "--name", "a b"]);
  const opts = args.slice(0, dash);
  const values = (flag) => opts.flatMap((v, i) => (v === flag ? [opts[i + 1]] : []));
  assert.deepEqual(values("--profile"), ["YouGame.Game.abc"]);
  assert.deepEqual(values("--runtime"), ["C:\\host", "C:\\cores"]);
  assert.deepEqual(values("--read"), ["C:\\rom.nes"]);
  assert.deepEqual(values("--write"), ["C:\\saves\\a"]);
  assert.deepEqual(values("--net"), ["none"]);
  assert.deepEqual(values("--max-memory"), ["4096"]);
  assert.deepEqual(values("--cwd"), ["C:\\saves\\a"]);
  assert.deepEqual(values("--env"), ["SDL_JOYSTICK_WGI=1"]);
  assert.deepEqual(values("--embed-parent"), ["42"]);
  assert.deepEqual(values("--embed-class"), ["SDL_app"]);
  assert.deepEqual(values("--embed-title"), ["yougame-libretro"]);
  // Nothing in the program's own arguments is read as a launcher option.
  assert.ok(!opts.includes("--name"));
});

test("only the app decides to run without the sandbox, and says why", () => {
  const launcher = "C:\\app\\yougame-sandbox.exe";
  assert.deepEqual(sandboxDecision({ platform: "win32", launcher, env: {} }), { sandboxed: true });
  assert.deepEqual(sandboxDecision({ platform: "win32", launcher, setting: true, env: {} }), { sandboxed: true });
  // Anything but an explicit false in the settings file keeps it on.
  for (const setting of [undefined, null, 0, "false", "off", {}]) assert.equal(sandboxDecision({ platform: "win32", launcher, setting, env: {} }).sandboxed, true, String(setting));
  for (const [o, reason] of [
    [{ platform: "darwin", launcher }, /platform/],
    [{ platform: "win32", launcher: null }, /missing/],
    [{ platform: "win32", launcher, env: { YOUGAME_SANDBOX: "off" } }, /YOUGAME_SANDBOX/],
    [{ platform: "win32", launcher, setting: false }, /settings/],
  ]) {
    const d = sandboxDecision(o);
    assert.equal(d.sandboxed, false);
    assert.match(d.reason, reason);
  }
  // Other values of the variable do not switch it off.
  assert.equal(sandboxDecision({ platform: "win32", launcher, env: { YOUGAME_SANDBOX: "0" } }).sandboxed, true);
});

test("how a sandboxed launch ended: ran, cannot exist here (run without, logged), or failed (refuse)", () => {
  assert.equal(SANDBOX_SETUP_FAILED, 120);
  assert.equal(SANDBOX_UNSUPPORTED, 121);
  const running = "sandbox: running pid 12 in AppContainer YouGame.Game.ab (S-1-15-2-1), network none\n";
  // It ran inside the sandbox: whatever the code, that is the game's own exit, never a reason to drop the sandbox.
  for (const code of [0, 120, 121, 122, 1, 3, 0xc0000005, 0xc0000135, null]) assert.equal(sandboxOutcome(code, `${running}core: boom\n`), "ran", String(code));
  // This Windows cannot make an AppContainer, or the launcher itself could not start (a spawn error, a missing DLL).
  assert.equal(sandboxOutcome(121, "sandbox: the AppContainer profile failed (error 0x80070005)\n"), "unsupported");
  assert.equal(sandboxOutcome(null, "", true), "unsupported");
  assert.equal(sandboxOutcome(0xc0000135, ""), "unsupported");
  assert.equal(sandboxOutcome(-1073741515, ""), "unsupported"); // the same status as a signed number
  for (const code of [0xc0000139, 0xc000007b, 0xc0000142]) assert.equal(sandboxOutcome(code, ""), "unsupported", code.toString(16));
  // Any other NTSTATUS before "running" (a crash, an access violation, a stack overflow) is not the
  // computer lacking a sandbox: refuse rather than run the game without it.
  for (const code of [0xc0000005, 0xc00000fd, 0xc0000409, 0xc000001d, -1073741819]) assert.equal(sandboxOutcome(code, ""), "failed", String(code));
  // The sandbox could not be set up here (a grant, the job), or the launcher was stopped first: refuse, never run unsandboxed.
  assert.equal(sandboxOutcome(120, "sandbox: cannot grant write on C:\\x (error 5)\n"), "failed");
  assert.equal(sandboxOutcome(null, ""), "failed");
  assert.equal(sandboxOutcome(1, ""), "failed");
  assert.equal(sandboxOutcome(0, ""), "failed");
  // A line the game writes cannot stand in for the launcher's own: only a full "running pid" line counts, at a line start.
  assert.equal(sandboxOutcome(120, "core says sandbox: running pid 1 in AppContainer x\n"), "failed");
  assert.match(SANDBOX_FAILED_MESSAGE, /sandbox/);
});

test("the save files of one game copy, and no other game's", () => {
  assert.equal(isSaveOf("zelda", "zelda.srm", true), true);
  assert.equal(isSaveOf("zelda", "zelda.state3", true), true);
  assert.equal(isSaveOf("zelda", "zelda.state.auto", true), true);
  assert.equal(isSaveOf("zelda", "Zelda.SRM", true), false, "the kind is matched exactly");
  assert.equal(isSaveOf("zelda", "ZELDA.srm", true), true, "the name folds case on Windows and macOS");
  assert.equal(isSaveOf("zelda", "ZELDA.srm", false), false, "but not on Linux");
  for (const f of ["zelda-2.srm", "zelda.srm.tmp", "zelda.cfg", "zelda.", "zelda", "zeld.srm", "xzelda.srm", "zelda.state10"]) assert.equal(isSaveOf("zelda", f, true), false, f);
});

test("the launcher gets only what Windows needs, never the app's secrets", () => {
  const env = launcherEnv({
    SystemRoot: "C:\\Windows",
    NUMBER_OF_PROCESSORS: "8",
    CLOUDFLARE_API_TOKEN: "secret",
    SUPABASE_SERVICE_ROLE_KEY: "secret",
    NODE_OPTIONS: "--require evil.js",
    ELECTRON_RUN_AS_NODE: "1",
    PATH: "C:\\evil;C:\\Windows\\System32",
    USERPROFILE: "C:\\Users\\me",
    APPDATA: "C:\\Users\\me\\AppData\\Roaming",
  });
  assert.equal(env.SystemRoot, "C:\\Windows");
  assert.equal(env.NUMBER_OF_PROCESSORS, "8");
  assert.equal(env.PATH, "C:\\Windows\\System32;C:\\Windows");
  for (const k of ["CLOUDFLARE_API_TOKEN", "SUPABASE_SERVICE_ROLE_KEY", "NODE_OPTIONS", "ELECTRON_RUN_AS_NODE", "USERPROFILE", "APPDATA"]) assert.equal(env[k], undefined, k);
  // Names are matched without regard to case, as Windows does.
  assert.equal(launcherEnv({ systemroot: "D:\\Win" }).SystemRoot, "D:\\Win");
});
