import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { walkDirectory, SCANNABLE_EXTENSIONS, SKIP_DIRS, readFileSafe } from "../walker";

describe("walkDirectory", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("yields scannable files in a flat directory", () => {
    fs.writeFileSync(path.join(tmpDir, "server.ts"), "// ts");
    fs.writeFileSync(path.join(tmpDir, "config.json"), "{}");
    fs.writeFileSync(path.join(tmpDir, "readme.md"), "# readme");

    const results = [...walkDirectory(tmpDir)];

    expect(results).toHaveLength(2);
    expect(results.some((f) => f.endsWith("server.ts"))).toBe(true);
    expect(results.some((f) => f.endsWith("config.json"))).toBe(true);
    // .md files should not be included
    expect(results.some((f) => f.endsWith("readme.md"))).toBe(false);
  });

  it("recurses into subdirectories", () => {
    const subDir = path.join(tmpDir, "src");
    fs.mkdirSync(subDir);
    fs.writeFileSync(path.join(subDir, "handler.ts"), "// handler");
    fs.writeFileSync(path.join(tmpDir, "index.js"), "// index");

    const results = [...walkDirectory(tmpDir)];

    expect(results).toHaveLength(2);
    expect(results.some((f) => f.endsWith("handler.ts"))).toBe(true);
    expect(results.some((f) => f.endsWith("index.js"))).toBe(true);
  });

  it("skips node_modules by default", () => {
    const nmDir = path.join(tmpDir, "node_modules", "some-pkg");
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, "index.js"), "// pkg");
    fs.writeFileSync(path.join(tmpDir, "main.ts"), "// main");

    const results = [...walkDirectory(tmpDir)];

    expect(results).toHaveLength(1);
    expect(results[0]).toMatch(/main\.ts$/);
  });

  it("skips .git directory by default", () => {
    const gitDir = path.join(tmpDir, ".git");
    fs.mkdirSync(gitDir);
    fs.writeFileSync(path.join(gitDir, "config"), "// git config");
    fs.writeFileSync(path.join(tmpDir, "app.ts"), "// app");

    const results = [...walkDirectory(tmpDir)];

    // .git/config has no scannable extension, app.ts is yielded
    expect(results).toHaveLength(1);
    expect(results[0]).toMatch(/app\.ts$/);
  });

  it("yields yaml and yml files", () => {
    fs.writeFileSync(path.join(tmpDir, "manifest.yaml"), "key: value");
    fs.writeFileSync(path.join(tmpDir, "action.yml"), "on: push");

    const results = [...walkDirectory(tmpDir)];

    expect(results).toHaveLength(2);
    expect(results.some((f) => f.endsWith("manifest.yaml"))).toBe(true);
    expect(results.some((f) => f.endsWith("action.yml"))).toBe(true);
  });

  it("returns empty array for an empty directory", () => {
    const results = [...walkDirectory(tmpDir)];
    expect(results).toHaveLength(0);
  });

  it("respects custom skipDirs option", () => {
    const customSkip = path.join(tmpDir, "custom_skip");
    fs.mkdirSync(customSkip);
    fs.writeFileSync(path.join(customSkip, "file.ts"), "// skip me");
    fs.writeFileSync(path.join(tmpDir, "keep.ts"), "// keep me");

    const results = [...walkDirectory(tmpDir, { skipDirs: new Set(["custom_skip"]) })];

    expect(results).toHaveLength(1);
    expect(results[0]).toMatch(/keep\.ts$/);
  });

  it("respects maxDepth option", () => {
    const deep = path.join(tmpDir, "a", "b", "c");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, "deep.ts"), "// deep");
    fs.writeFileSync(path.join(tmpDir, "shallow.ts"), "// shallow");

    // maxDepth=1 should find shallow.ts and a/b level but not a/b/c
    const results = [...walkDirectory(tmpDir, { maxDepth: 1 })];

    expect(results.some((f) => f.endsWith("shallow.ts"))).toBe(true);
    expect(results.some((f) => f.endsWith("deep.ts"))).toBe(false);
  });
});

describe("SCANNABLE_EXTENSIONS", () => {
  it("includes expected extensions", () => {
    expect(SCANNABLE_EXTENSIONS.has(".json")).toBe(true);
    expect(SCANNABLE_EXTENSIONS.has(".ts")).toBe(true);
    expect(SCANNABLE_EXTENSIONS.has(".js")).toBe(true);
    expect(SCANNABLE_EXTENSIONS.has(".yaml")).toBe(true);
    expect(SCANNABLE_EXTENSIONS.has(".yml")).toBe(true);
  });

  it("does not include markdown or text files", () => {
    expect(SCANNABLE_EXTENSIONS.has(".md")).toBe(false);
    expect(SCANNABLE_EXTENSIONS.has(".txt")).toBe(false);
  });
});

describe("SKIP_DIRS", () => {
  it("includes common build/dependency directories", () => {
    expect(SKIP_DIRS.has("node_modules")).toBe(true);
    expect(SKIP_DIRS.has(".git")).toBe(true);
    expect(SKIP_DIRS.has("dist")).toBe(true);
  });
});

describe("readFileSafe", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-read-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads a file that exists", () => {
    const filePath = path.join(tmpDir, "test.ts");
    fs.writeFileSync(filePath, "const x = 1;");
    expect(readFileSafe(filePath)).toBe("const x = 1;");
  });

  it("returns null for a nonexistent file", () => {
    expect(readFileSafe("/nonexistent/path/file.ts")).toBeNull();
  });
});
