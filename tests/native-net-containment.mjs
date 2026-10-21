// Windows only: a native build reaches the network only when YouGame approved its game.
//
//   node tests/native-net-containment.mjs     (after npm run build and native:build)
//
// Runs sandbox-probe.exe as a native build through the real launcher, with the grants launchPlan
// and nativeSandbox give it (dist/native-launch.js), first for a game not approved to go online,
// then for an approved one. Not approved: a TCP connection and the lookup of a name that exists
// must both fail. Approved: both must work.
// The sandbox cannot stop screen capture, so the network is what stands between a build and
// sending out the player's screen (docs/DESKTOP_SANDBOX.md, "Online only for approved games").
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
for (const internet of [false, true]) {
  // The default spec asks for the internet, as most games do; launchPlan decides whether it gets it.
  const plan = launchPlan({
    platform: "windows",
    sandboxed: true,
    testing: false,
    spec: null,
    internet,
  });
  const spec = nativeSandbox({
    gameId: `native-net-${internet ? "approved" : "offline"}`,
    build,
    data,
    disc: null,
    spec: plan.spec,
    env: {},
  });
  const got = parse((await run(sandboxArgs(spec, probe, attempts))).out);
  const want = internet ? "allowed" : "denied";
  console.log(`-- ${internet ? "approved" : "not approved"} (net ${spec.net})`);
  const token = got.get("token");
  if (!token || !/appcontainer=yes/.test(token.detail))
    failures.push(`${internet}: not in an AppContainer (${token?.detail ?? "no answer"})`);
  for (const k of ["connect 1.1.1.1:443", "dns one.one.one.one"]) {
    const r = got.get(k);
    console.log(`  ${k}: ${r ? `${r.verdict} ${r.detail}` : "no answer"}`);
    if (!r || r.verdict !== want)
      failures.push(
        `${internet ? "approved" : "not approved"}: ${k} should be ${want}, was ${r ? `${r.verdict} ${r.detail}` : "no answer"}`,
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
