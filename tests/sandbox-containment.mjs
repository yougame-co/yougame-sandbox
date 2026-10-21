// Containment, on Windows: what a game that took over its emulator could do inside the sandbox.
// sandbox-probe (native/sandbox/probe.cpp, built next to the launcher, never shipped) stands in
// for a compromised yougame-libretro: it runs through yougame-sandbox with exactly the grants the
// app gives the emulator (dist/sandbox-policy.js embedSandbox) in a copy of the app's folder
// layout, tries what malware would, and every answer is checked. The same probe also runs once
// outside the sandbox on the attempts that should succeed there, so a "denied" is the sandbox's
// doing and not a broken test. Manual: `npm run build` and `npm run native:build` first.
//   node tests/sandbox-containment.mjs
// It presses F13 (a key no keyboard has) a few times for the key-logging check.
// Prints CONTAINMENT OK and exits 0, or each failed expectation and exits 1.
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  console.log("sandbox containment: Windows only, skipped");
  process.exit(0);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bin = path.join(root, "native", "bin", `win32-${process.arch}`);
const launcher = path.join(bin, "yougame-sandbox.exe");
const probeBuilt = path.join(root, "native", `build-sandbox-${process.arch}`, "Release", "sandbox-probe.exe");
for (const f of [launcher, probeBuilt, path.join(root, "dist", "sandbox-policy.js")])
  if (!fs.existsSync(f)) {
    console.error(`missing ${f}: run npm run build and npm run native:build`);
    process.exit(2);
  }
const { embedSandbox, sandboxArgs } = createRequire(import.meta.url)(path.join(root, "dist", "sandbox-policy.js"));

// The app's layout under a fresh folder in the user's temp (inside the user profile, like userData).
const top = fs.mkdtempSync(path.join(os.tmpdir(), "yg-containment-"));
const hostDir = path.join(top, "controllers");
const emu = path.join(top, "emulator");
const cores = path.join(emu, "cores"), roms = path.join(emu, "roms");
const saves = path.join(emu, "saves", "containment-test"), system = path.join(emu, "system", "containment-test");
const otherSaves = path.join(emu, "saves", "another-game");
for (const d of [hostDir, cores, roms, saves, system, otherSaves, path.join(top, "Network")]) fs.mkdirSync(d, { recursive: true });
const probe = path.join(hostDir, "sandbox-probe.exe");
fs.copyFileSync(probeBuilt, probe);
const core = path.join(cores, "fake_libretro.dll");
fs.writeFileSync(core, "core");
const rom = path.join(roms, "containment-test.nes");
fs.writeFileSync(rom, "rom");
const appWrittenSave = path.join(saves, "containment-test.state1");
fs.writeFileSync(appWrittenSave, "the account's copy");
const otherSave = path.join(otherSaves, "another-game.srm");
fs.writeFileSync(otherSave, "another game's save");
// Stand-ins for what lives in a user profile: the app's own cookie jar, a key, a document.
const cookies = path.join(top, "Network", "Cookies");
fs.writeFileSync(cookies, "session cookie");
const canary = path.join(top, "id_ed25519");
fs.writeFileSync(canary, "private key");
const startup = path.join(os.homedir(), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "yougame-probe.bat");

// Something to connect to on loopback and on this machine's LAN address.
const server = net.createServer((s) => s.end());
await new Promise((r) => server.listen(0, "0.0.0.0", r));
const port = server.address().port;
const lan = Object.values(os.networkInterfaces()).flat().find((a) => a && a.family === "IPv4" && !a.internal)?.address;

const spec = embedSandbox({ name: "containment-test", hostDir, coresDir: cores, rom, saves, system });
// Each attempt and what the sandbox must answer. `control: true` also runs outside the sandbox and must be allowed there.
const attempts = [
  ["token", "allowed", /appcontainer=yes integrity=0x1000/],
  [`read=${rom}`, "allowed"],
  [`read=${core}`, "allowed"],
  [`write=${path.join(saves, "containment-test.srm")}`, "allowed"],
  [`write=${path.join(system, "core-cache.bin")}`, "allowed"],
  // A save the app itself wrote (the account's copy, before a launch) is still the game's to overwrite.
  [`write=${appWrittenSave}`, "allowed"],
  [`read=${otherSave}`, "denied", null, true],
  [`write=${path.join(otherSaves, "another-game.state1")}`, "denied", null, true],
  [`read=${cookies}`, "denied", null, true],
  [`read=${canary}`, "denied", null, true],
  [`list=${os.homedir()}`, "denied", null, true],
  [`list=${path.join(os.homedir(), "Documents")}`, "denied", null, true],
  [`read=${path.join(os.homedir(), "NTUSER.DAT")}`, "denied"],
  [`write=${path.join(top, "dropped.exe")}`, "denied", null, true],
  [`write=${path.join(cores, "fake_libretro.dll")}`, "denied", null, true],
  [`write=${path.join(hostDir, "yougame-libretro.exe")}`, "denied", null, true],
  [`write=${rom}`, "denied", null, true],
  [`write=${startup}`, "denied"],
  ["regwrite=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "denied"],
  [`connect=127.0.0.1:${port}`, "denied", null, true],
  ...(lan ? [[`connect=${lan}:${port}`, "denied", null, true]] : []),
  ["connect=1.1.1.1:443", "denied"],
  // Without internetClient, a name that exists does not resolve either: Windows answers "no such
  // name" without sending the query (DESKTOP_SANDBOX.md, measured with pktmon).
  ["dns=one.one.one.one", "denied", null, true],
  [`spawn=${path.join(process.env.SystemRoot || "C:\\Windows", "System32", "cmd.exe")}`, "denied", null, true],
  ["clipboard", "denied"],
  [`openprocess=${process.pid}`, "denied", null, true],
  ["alloc=6144", "denied", null, true],
  ["screen", null],
  ["keys=9000", null],
];

function run(command, args, keys) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    if (keys) {
      // F13 pressed while the probe listens (after PowerShell's own start-up).
      setTimeout(() => {
        try {
          execFileSync("powershell", ["-NoProfile", "-Command", `Add-Type -Name K -Namespace W -MemberDefinition '[DllImport("user32.dll")] public static extern void keybd_event(byte v, byte s, uint f, System.UIntPtr e);'; for($i=0;$i -lt 6;$i++){[W.K]::keybd_event(0x7C,0,0,[System.UIntPtr]::Zero); Start-Sleep -Milliseconds 40; [W.K]::keybd_event(0x7C,0,2,[System.UIntPtr]::Zero); Start-Sleep -Milliseconds 120}`]);
        } catch {}
      }, 1000);
    }
    child.on("exit", (code) => resolve({ code, out, err }));
  });
}

const parse = (out) => {
  const m = new Map();
  for (const line of out.split(/\r?\n/)) {
    const r = /^(.*?) (allowed|denied) ?(.*)$/.exec(line);
    if (r) m.set(r[1], { verdict: r[2], detail: r[3] });
  }
  return m;
};
const key = (a) => {
  const [k, v] = a.split(/=(.*)/s);
  return v === undefined ? k : k === "keys" ? "keyhook" : k === "alloc" ? `alloc ${v}MB` : `${k} ${v}`;
};

const failures = [];
const keysAt = attempts.findIndex(([a]) => a.startsWith("keys="));
const sandboxed = await run(launcher, sandboxArgs(spec, probe, attempts.map(([a]) => a)), keysAt >= 0);
const inside = parse(sandboxed.out);
// Nothing outside the grant changed on disk (checked before the control run, which may write there).
const untouched = !fs.existsSync(path.join(top, "dropped.exe")) && !fs.existsSync(startup) && fs.readFileSync(otherSave, "utf8") === "another game's save" && fs.readFileSync(rom, "utf8") === "rom" && fs.readFileSync(core, "utf8") === "core";
const ctl = attempts.filter(([, , , c]) => c).map(([a]) => a);
const outside = parse((await run(probe, [...ctl, "keys=9000"], true)).out);
server.close();

console.log("attempt                                                            sandboxed  outside");
for (const [a, want, detailRe, control] of attempts) {
  const k = key(a);
  const got = inside.get(k);
  const ctlGot = control ? outside.get(k) : null;
  const label = k.replace(top, "<app>").replace(os.homedir(), "~");
  console.log(`  ${label.padEnd(64).slice(0, 64)} ${(got?.verdict ?? "-").padEnd(10)} ${ctlGot?.verdict ?? ""}   ${got?.detail ?? ""}`);
  if (!got) {
    failures.push(`${k}: no answer from the sandboxed probe`);
    continue;
  }
  if (want && got.verdict !== want) failures.push(`${k}: ${got.verdict} in the sandbox, expected ${want} (${got.detail})`);
  if (detailRe && !detailRe.test(got.detail)) failures.push(`${k}: ${got.detail}`);
  if (control && ctlGot?.verdict !== "allowed") failures.push(`${k}: the control run outside the sandbox was ${ctlGot?.verdict ?? "missing"} (${ctlGot?.detail ?? ""}), so the test proves nothing`);
}
// Key logging: blocked inside while the same key presses are seen outside.
const hookIn = inside.get("keyhook"), pollIn = inside.get("keypoll"), hookOut = outside.get("keyhook");
if (hookOut?.verdict !== "allowed") failures.push(`key presses were not seen outside the sandbox either (${hookOut?.detail}); the key-logging check proves nothing`);
else {
  console.log(`  key logging: outside ${hookOut.detail}; inside hook ${hookIn?.detail}, polling ${pollIn?.detail}`);
  if (hookIn?.verdict !== "denied" || pollIn?.verdict !== "denied") failures.push("the sandboxed probe saw keys typed into another window");
}
if (!untouched) failures.push("a file outside the grant was changed by the sandboxed probe");
const strict = inside.get("strict-handles");
console.log(`  strict handle checks inside: ${strict?.verdict === "allowed" ? "on" : "off"} (${strict?.detail}); Windows turns them on for every AppContainer`);
// The job: killing the launcher (what the app does to a host that will not quit) takes the sandboxed program with it.
{
  const child = spawn(launcher, sandboxArgs(spec, probe, ["keys=30000"]), { stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  child.stderr.on("data", (d) => (err += d));
  for (let i = 0; i < 50 && !/running pid ([0-9]+)/.test(err); i++) await new Promise((r) => setTimeout(r, 100));
  const pid = Number(/running pid ([0-9]+)/.exec(err)?.[1]);
  child.kill();
  await new Promise((r) => setTimeout(r, 1500));
  const alive = pid && execFileSync("tasklist", ["/FI", `PID eq ${pid}`, "/NH"], { encoding: "utf8" }).includes(String(pid));
  console.log(`  killing the launcher: the sandboxed program (pid ${pid}) is ${alive ? "STILL RUNNING" : "gone"}`);
  if (!pid || alive) failures.push("the sandboxed program outlived its launcher");
}
console.log(`  launcher: ${sandboxed.err.split(/\r?\n/).filter((l) => l.startsWith("sandbox:")).join(" | ")}`);
fs.rmSync(top, { recursive: true, force: true });
if (failures.length) {
  for (const f of failures) console.log(`  FAIL ${f}`);
  console.log("CONTAINMENT FAILED");
  process.exit(1);
}
console.log("CONTAINMENT OK");
