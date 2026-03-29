import * as fs from "fs";
import * as path from "path";

/** File extensions that the scanner examines. */
export const SCANNABLE_EXTENSIONS = new Set([
  ".json",
  ".ts",
  ".js",
  ".yaml",
  ".yml",
]);

/** Options for the directory walker. */
export interface WalkOptions {
  /** Directories to skip (e.g. node_modules, .git). Defaults to SKIP_DIRS. */
  skipDirs?: Set<string>;
  /** Maximum directory depth to traverse. Defaults to 20. */
  maxDepth?: number;
}

/** Default directories that are always skipped. */
export const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "build", "coverage"]);

/**
 * Recursively walk a directory and yield paths to scannable files.
 *
 * Only files whose extensions are in SCANNABLE_EXTENSIONS are yielded.
 * Directories in skipDirs are not descended into.
 *
 * @param dir - Absolute path to the directory to walk.
 * @param options - Optional walk configuration.
 * @yields Absolute file paths.
 */
export function* walkDirectory(
  dir: string,
  options: WalkOptions = {},
  _depth = 0,
): Generator<string> {
  const skipDirs = options.skipDirs ?? SKIP_DIRS;
  const maxDepth = options.maxDepth ?? 20;

  if (_depth > maxDepth) {
    return;
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    // Unreadable directory — skip silently
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!skipDirs.has(entry.name)) {
        yield* walkDirectory(fullPath, options, _depth + 1);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCANNABLE_EXTENSIONS.has(ext)) {
        yield fullPath;
      }
    }
  }
}

/**
 * Read a file and return its contents, or null if the file cannot be read.
 *
 * @param filePath - Absolute path to the file.
 * @returns File contents as a string, or null on error.
 */
export function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}
