// Generates only an isolated fake Steam tree; never discovers or touches a real Steam install.
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const INSTALL_DIR = "YG Steam Probe MCC";
export const BUILD_ID = "424242";

export async function makeSteamLayout(destination) {
  const root = path.resolve(destination);
  // Refuse an existing destination. All writes below belong to the fresh fixture directory.
  await mkdir(root);
  const steamapps = path.join(root, "steamapps");
  const game = path.join(steamapps, "common", INSTALL_DIR);
  await mkdir(path.join(game, "halo3"), { recursive: true });
  const vdfRoot = root.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  await writeFile(path.join(steamapps, "libraryfolders.vdf"), `"libraryfolders"
{
  "0"
  {
    "path" "${vdfRoot}"
    "apps" { "976730" "128" }
  }
}
`, { flag: "wx" });
  await writeFile(path.join(steamapps, "appmanifest_976730.acf"), `"AppState"
{
  "appid" "976730"
  "name" "YG Steam Probe (fake MCC)"
  "installdir" "${INSTALL_DIR}"
  "StateFlags" "4"
  "buildid" "${BUILD_ID}"
}
`, { flag: "wx" });
  await writeFile(path.join(game, "halo3", "halo3.dll"), Buffer.from("YouGame fake Steam probe DLL stub. No executable code.\n".repeat(4)), { flag: "wx" });
  return { root, game, appid: 976730, buildid: BUILD_ID };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error("usage: node make-steam-layout.mjs <new-fixture-directory>");
  console.log(JSON.stringify(await makeSteamLayout(process.argv[2])));
}
