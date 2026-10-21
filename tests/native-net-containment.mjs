// Windows only: a native build is online unless its game is blocked; test builds run offline.
//
//   node tests/native-net-containment.mjs     (after npm run build and native:build)
//
// Runs sandbox-probe.exe as a native build through the real launcher, with the grants launchPlan
// and nativeSandbox give it (dist/native-launch.js): blocked, online with net "internet", online
// with net "yougame", and a crowd-coding test build. Only online with net "internet" may connect
// over TCP and look up a name. With net "yougame", the app opens YouGame connections for the build,
// while the build itself gets --net none.
// The sandbox cannot stop screen capture, so the network is what stands between a build and
// sending out the player's screen (docs/DESKTOP_SANDBOX.md).
// Prints NATIVE NET OK and exits 0, or each failed expectation and exits 1.
import { spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  console.log("native net containment: Windows only, skipped");
  process.exit(0);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const launcher = path.join(root, "native", "bin", `win32-${process.arch}`, "yougame-sandbox.exe");
const probeBuilt = path.join(
  root,
  "native",
  `build-sandbox-${process.arch}`,
  "Release",
  "sandbox-probe.exe",
);
for (const f of [launcher, probeBuilt, path.join(root, "dist", "native-launch.js")])
  if (!fs.existsSync(f)) {
    console.error(`missing ${f}: run npm run build and npm run native:build`);
    process.exit(2);
  }
const require = createRequire(import.meta.url);
const { launchPlan, nativeSandbox, DEFAULT_LAUNCH_SPEC } = require(
  path.join(root, "dist", "native-launch.js"),
);
const { sandboxArgs } = require(path.join(root, "dist", "sandbox-policy.js"));

// A build folder (read + execute) and a data folder (read + write), as the app lays them out.
const top = fs.mkdtempSync(path.join(os.tmpdir(), "yg-native-net-"));
const build = path.join(top, "build"),
  data = path.join(top, "data");
fs.mkdirSync(build);
fs.mkdirSync(data);
const probe = path.join(build, "game.exe");
fs.copyFileSync(probeBuilt, probe);

const attempts = ["token", "connect=1.1.1.1:443", "dns=one.one.one.one"];

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(launcher, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", () => {});
    child.on("exit", (code) => resolve({ code, out }));
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

const failures = [];
const cases = [
  { name: "blocked game", id: "blocked", internet: false, net: "internet", branch: false, want: "denied" },
  { name: 'online game, net "internet"', id: "internet", internet: true, net: "internet", branch: false, want: "allowed" },
  { name: 'online game, net "yougame"', id: "yougame", internet: true, net: "yougame", branch: false, want: "denied" },
  { name: 'crowd-coding test build, net "internet"', id: "branch", internet: true, net: "internet", branch: true, want: "denied" },
];
for (const c of cases) {
  const plan = launchPlan({
    platform: "windows",
    sandboxed: true,
    testing: false,
    spec: { ...DEFAULT_LAUNCH_SPEC, net: c.net },
    internet: c.internet,
    branch: c.branch,
  });
  if (plan.error || !plan.spec) {
    failures.push(`${c.name}: ${plan.error ?? "no launch spec"}`);
    console.log(`-- ${c.name}: no launch plan`);
    continue;
  }
  const spec = nativeSandbox({
    gameId: `native-net-${c.id}`,
    build,
    data,
    disc: null,
    spec: plan.spec,
    env: {},
  });
  const args = sandboxArgs(spec, probe, attempts);
  const net = args[args.indexOf("--net") + 1];
  const wantNet = c.want === "allowed" ? "internet" : "none";
  if (!args.includes("--net") || net !== wantNet)
    failures.push(`${c.name}: launch args should contain --net ${wantNet}`);
  const { code, out } = await run(args);
  const got = parse(out);
  if (code !== 0) failures.push(`${c.name}: launcher exited ${code}`);
  const token = got.get("token");
  if (!token || !/appcontainer=yes/.test(token.detail))
    failures.push(`${c.name}: not in an AppContainer (${token?.detail ?? "no answer"})`);
  const checks = ["connect 1.1.1.1:443", "dns one.one.one.one"];
  console.log(`-- ${c.name} (--net ${net}): ${checks.map((k) => `${k}: ${got.get(k)?.verdict ?? "no answer"}`).join(", ")}`);
  for (const k of checks) {
    const r = got.get(k);
    if (!r || r.verdict !== c.want)
      failures.push(
        `${c.name}: ${k} should be ${c.want}, was ${r ? `${r.verdict} ${r.detail}` : "no answer"}`,
      );
  }
}
fs.rmSync(top, { recursive: true, force: true });
if (DEFAULT_LAUNCH_SPEC.net !== "internet")
  failures.push("the default spec no longer asks for the internet; update this test");
if (failures.length) {
  for (const f of failures) console.log(`FAIL ${f}`);
  process.exit(1);
}
console.log("NATIVE NET OK");
