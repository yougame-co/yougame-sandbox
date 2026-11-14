const { test } = require("node:test");
const assert = require("node:assert/strict");
const { sandboxArgs } = require("../dist/sandbox-policy.js");
const { parseLaunchSpec, launchArgs, nativeSandbox, EXTRA_DISCS_UA_TOKEN } = require("../dist/native-launch.js");

const UA = `YouGame/0.13 ${EXTRA_DISCS_UA_TOKEN}`;
const BRAWL = { system: "wii", id: "RSBE01", optional: true, label: "Super Smash Bros. Brawl" };
const spec = (extra) => JSON.stringify({ version: 1, args: ["--iso", "{disc}", "--brawl-disc", "{disc:brawl}"], disc: true, discs: { brawl: BRAWL }, ...extra });
const parsed = (text, ua = UA) => {
  const r = parseLaunchSpec(text, ua);
  assert.ok("spec" in r, r.error);
  return r.spec;
};
const paths = (discs) => ({ build: "B", data: "D", disc: "M.iso", discs });

test("named extra discs parse only for an app that advertises them", () => {
  assert.deepEqual(parsed(spec()).discs, { brawl: BRAWL });
  assert.deepEqual(parseLaunchSpec(spec(), ""), { error: 'unknown field "discs"' });
  assert.deepEqual(parseLaunchSpec(spec(), "YouGame/0.12 YouGameDirect/1 YouGameSteamBase/1"), { error: 'unknown field "discs"' });
  // A spec without discs is unchanged by the token.
  assert.equal(parsed(JSON.stringify({ version: 1, args: ["{disc}"], disc: true })).discs, undefined);
  // Optional without a label, and a GameCube disc.
  assert.deepEqual(parsed(spec({ args: ["{disc:extra_2}"], discs: { extra_2: { system: "gc", id: "GALE01", optional: false } } })).discs, { extra_2: { system: "gc", id: "GALE01", optional: false } });
});

test("named extra discs refuse what is wrong, in the spec's own words", () => {
  const err = (extra) => parseLaunchSpec(spec(extra), UA).error;
  assert.equal(err({ discs: { base: BRAWL } }), 'disc name "base" is reserved');
  assert.equal(err({ discs: { Brawl: BRAWL } }), 'disc name "Brawl" must be 1 to 16 of a-z 0-9 _');
  assert.equal(err({ discs: { abcdefghijklmnopq: BRAWL } }), 'disc name "abcdefghijklmnopq" must be 1 to 16 of a-z 0-9 _');
  assert.equal(err({ discs: { "": BRAWL } }), 'disc name "" must be 1 to 16 of a-z 0-9 _');
  assert.equal(err({ discs: {} }), "discs must be an object of 1 to 4 named discs");
  assert.equal(err({ discs: [] }), "discs must be an object of 1 to 4 named discs");
  assert.equal(err({ discs: { a: BRAWL, b: BRAWL, c: BRAWL, d: BRAWL, e: BRAWL } }), "discs must be an object of 1 to 4 named discs");
  assert.equal(err({ discs: { brawl: { ...BRAWL, path: "x" } } }), "discs.brawl must be an object with system, id and optional");
  assert.equal(err({ discs: { brawl: { ...BRAWL, system: "ps2" } } }), 'discs.brawl.system must be "gc" or "wii"');
  for (const id of ["RSBE0", "rsbe01", "RSBE01X", 1])
    assert.equal(err({ discs: { brawl: { ...BRAWL, id } } }), "discs.brawl.id must be a 6-character game id (A-Z 0-9)");
  const { optional: _o, ...noOptional } = BRAWL;
  assert.equal(err({ discs: { brawl: noOptional } }), "discs.brawl.optional must be true or false");
  for (const label of ["", " ", "a\u0007", "x".repeat(81), 3])
    assert.equal(err({ discs: { brawl: { ...BRAWL, label } } }), "discs.brawl.label must be 1 to 80 printable characters");
  // Placeholders: declared names only, and only {disc:...} takes a name.
  assert.equal(err({ args: ["{disc:melee}"] }), "{disc:melee} needs discs.melee");
  assert.equal(parseLaunchSpec(JSON.stringify({ version: 1, args: ["{disc:brawl}"] }), UA).error, "{disc:brawl} needs discs.brawl");
  assert.equal(err({ args: ["{build:brawl}"] }), "unknown placeholder {build:brawl}");
  assert.equal(err({ args: ["{disc:Brawl}"] }), 'stray "{" in "{disc:Brawl}"');
  // An extra disc does not stand in for the base disc.
  assert.equal(err({ args: ["{disc}", "{disc:brawl}"], disc: false }), '{disc} needs "disc": true');
});

test("launchArgs places a picked extra disc like the base disc", () => {
  const s = parsed(spec({ args: ["--iso", "{disc}", "--brawl-disc", "{disc:brawl}", "--root={disc:brawl}/files"] }));
  assert.deepEqual(launchArgs(s, paths({ brawl: "W.iso" }), "\\"), ["--iso", "M.iso", "--brawl-disc", "W.iso", "--root=W.iso\\files"]);
});

test("launchArgs drops an optional extra disc the player did not pick, with its bare flag", () => {
  const s = parsed(spec({ args: ["--iso", "{disc}", "--brawl-disc", "{disc:brawl}", "--root={disc:brawl}", "-v", "{data}/x", "--brawl", "--keep"] }));
  const want = ["--iso", "M.iso", "-v", "D/x", "--brawl", "--keep"];
  assert.deepEqual(launchArgs(s, paths(undefined), "/"), want);
  assert.deepEqual(launchArgs(s, paths({}), "/"), want);
  assert.deepEqual(launchArgs(s, paths({ brawl: null }), "/"), want);
  assert.deepEqual(launchArgs(s, paths({ brawl: "" }), "/"), want);
  // A value before it is not a flag, so it stays; so does a flag with "=" or a placeholder.
  for (const [before, kept] of [["value", ["value"]], ["--a=b", ["--a=b"]], ["--out={data}", ["--out=D"]]])
    assert.deepEqual(launchArgs(parsed(spec({ args: [before, "{disc:brawl}"] })), paths(undefined), "/"), kept);
  // Two placeholders in a row drop only the one flag before the first.
  assert.deepEqual(launchArgs(parsed(spec({ args: ["-a", "-b", "{disc:brawl}", "{disc:brawl}"] })), paths(undefined), "/"), ["-a"]);
});

test("launchArgs refuses a required extra disc the player did not pick", () => {
  const s = parsed(spec({ discs: { brawl: { ...BRAWL, optional: false } } }));
  assert.throws(() => launchArgs(s, paths({ brawl: null }), "/"), /this game also plays on your own Super Smash Bros\. Brawl disc: pick it first/);
  const unlabeled = parsed(spec({ discs: { brawl: { system: "wii", id: "RSBE01", optional: false } } }));
  assert.throws(() => launchArgs(unlabeled, paths(undefined), "/"), /your own brawl disc: pick it first/);
  assert.deepEqual(launchArgs(s, paths({ brawl: "W.iso" }), "/"), ["--iso", "M.iso", "--brawl-disc", "W.iso"]);
});

test("the sandbox reads each picked extra disc, alone and read-only, and nothing undeclared", () => {
  const s = parsed(spec());
  const sb = (discs) => nativeSandbox({ gameId: "g", build: "b", data: "d", disc: "E:\\Melee.iso", discs, spec: s, env: {} });
  const picked = sb({ brawl: "F:\\Brawl.iso" });
  assert.deepEqual(picked.read, ["E:\\Melee.iso", "F:\\Brawl.iso"]);
  assert.deepEqual(picked.write, ["d"]);
  assert.deepEqual(picked.exec, ["b"]);
  const args = sandboxArgs(picked, "game.exe", []);
  assert.equal(args[args.indexOf("F:\\Brawl.iso") - 1], "--read");
  assert.ok(!args.includes("--exec") || args[args.indexOf("--exec") + 1] !== "F:\\Brawl.iso");
  assert.deepEqual(sb({ brawl: null }).read, ["E:\\Melee.iso"]);
  assert.deepEqual(sb(undefined).read, ["E:\\Melee.iso"]);
  // A name the spec does not declare is never granted.
  assert.deepEqual(sb({ brawl: "F:\\Brawl.iso", other: "G:\\x.iso" }).read, ["E:\\Melee.iso", "F:\\Brawl.iso"]);
});
