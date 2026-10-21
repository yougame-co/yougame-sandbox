// The save files a game copy owns: what the sandbox lets an emulator write (sandbox-policy.ts grants
// its saves folder) and what the app reads back afterwards (emulator.ts). Pure, for the tests.

/** A game copy's save name (web/src/lib/emulators.ts saveName): letters, digits and dashes, no dots. */
export const SAVE_NAME = /^[a-z0-9-]{1,120}$/i;

/** A save file's kind in the saves folder: the cartridge save, or one of the state slots the host writes. */
const SAVE_FILE = /^(srm|state[0-9]?|state\.auto)$/;
export function checkSaveFile(name: unknown, file: unknown): { name: string; file: string } | { error: string } {
  if (typeof name !== "string" || !SAVE_NAME.test(name)) return { error: "bad save name" };
  if (typeof file !== "string" || !SAVE_FILE.test(file)) return { error: "bad save file" };
  return { name, file };
}

/**
 * Whether `file` (a name in a folder) is one of the save files of the game copy `name`:
 * `<name>.srm`, `<name>.state3`… and nothing else (names have no dots, so no other game's
 * file can match). `foldCase` where the file system ignores case (Windows, macOS).
 */
export function isSaveOf(name: string, file: string, foldCase: boolean): boolean {
  if (file.length <= name.length + 1) return false;
  const head = file.slice(0, name.length + 1);
  if ((foldCase ? head.toLowerCase() : head) !== `${foldCase ? name.toLowerCase() : name}.`) return false;
  return "file" in checkSaveFile(name, file.slice(name.length + 1));
}
