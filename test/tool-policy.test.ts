import { mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  BUILTIN_TOOL_POLICIES,
  canonicalizeToolPath,
  extractToolPaths,
  formatToolPathArgument,
  getToolPolicy,
  mergeToolPolicies,
  parseToolPolicies,
  type ToolPathArgument,
} from "../src/tool-policy.ts";

const required = (name: string): ToolPathArgument => ({ name, required: true, glob: false });
const optionalGlob = (name: string): ToolPathArgument => ({ name, required: false, glob: true });

test("conflicting policies merge to the stricter write access and require every path", () => {
  const merged = mergeToolPolicies(
    { copy: { access: "read", pathArguments: ["source"] } },
    { copy: { access: "write", pathArguments: ["destination"] } },
  );

  assert.deepEqual(merged.copy, {
    access: "write",
    pathArguments: [required("source"), required("destination")],
  });
});

test("configured policies for built-in tools replace path arguments instead of unioning", () => {
  const merged = mergeToolPolicies(BUILTIN_TOOL_POLICIES, {
    read: { access: "read", pathArguments: ["file"] },
    write: { access: "write", pathArguments: ["target"] },
  });

  assert.deepEqual(merged.read, { access: "read", pathArguments: [required("file")] });
  assert.deepEqual(merged.write, { access: "write", pathArguments: [required("target")] });
  assert.deepEqual(merged.edit, { access: "write", pathArguments: [required("path")] });
  // Tools shipped by external plugins are never built in; they only exist once
  // a config layer declares them.
  assert.deepEqual(Object.keys(BUILTIN_TOOL_POLICIES), ["read", "write", "edit"]);
});

test("malformed policies are ignored without removing valid policy layers", () => {
  const parsed = parseToolPolicies({
    valid: { access: "write", pathArguments: ["path", "path"] },
    noPaths: { access: "write", pathArguments: [] },
    wrongAccess: { access: "execute", pathArguments: ["path"] },
    wrongShape: "path",
    malformedArgument: { access: "write", pathArguments: ["path", { name: "other", glob: "yes" }] },
    namelessArgument: { access: "write", pathArguments: [{ required: false }] },
  });

  assert.deepEqual(parsed, {
    valid: { access: "write", pathArguments: [required("path")] },
  });

  const merged = mergeToolPolicies(
    { replace: { access: "write", pathArguments: ["path"] } },
    { replace: { access: "write", pathArguments: [] } },
  );
  assert.deepEqual(merged.replace, { access: "write", pathArguments: [required("path")] });
});

test("path extraction checks every configured argument and fails closed", () => {
  const policy = {
    access: "write" as const,
    pathArguments: [required("source"), required("destination")],
  };

  assert.deepEqual(extractToolPaths({ source: "a", destination: "b" }, policy, "/cwd"), {
    ok: true,
    paths: ["a", "b"],
  });
  assert.deepEqual(extractToolPaths({ source: "a" }, policy, "/cwd"), {
    ok: false,
    reason: 'path argument "destination" must be a non-empty string',
  });
  assert.deepEqual(extractToolPaths({ source: "a", destination: "\0bad" }, policy, "/cwd"), {
    ok: false,
    reason: 'path argument "destination" must not contain NUL bytes',
  });
});

test("an omitted optional path argument is authorized as the session cwd", () => {
  const policy = { access: "read" as const, pathArguments: [optionalGlob("path")] };

  assert.deepEqual(extractToolPaths({ pattern: "needle" }, policy, "/cwd"), {
    ok: true,
    paths: ["/cwd"],
  });
  assert.deepEqual(extractToolPaths({ path: "   " }, policy, "/cwd"), {
    ok: true,
    paths: ["/cwd"],
  });
  assert.deepEqual(extractToolPaths({ path: "\0bad" }, policy, "/cwd"), {
    ok: false,
    reason: 'path argument "path" must not contain NUL bytes',
  });
});

test("glob arguments are reduced to the literal prefix of every alternative", () => {
  const policy = { access: "read" as const, pathArguments: [optionalGlob("path")] };
  const paths = (value: string) => {
    const extracted = extractToolPaths({ path: value }, policy, "/cwd");
    assert.equal(extracted.ok, true);
    return extracted.ok ? extracted.paths : [];
  };

  assert.deepEqual(paths("src/"), ["src/"]);
  assert.deepEqual(paths("src/**/*.ts"), ["src"]);
  assert.deepEqual(paths("/etc/*"), ["/etc"]);
  assert.deepEqual(paths("~/notes/*.md"), ["~/notes"]);
  assert.deepEqual(paths("test/,lib/*.js"), ["test/", "lib"]);
  // A wildcard in the first segment can only reach the cwd itself.
  assert.deepEqual(paths("*.ts"), ["."]);
  // Brace alternations are expanded so no alternative escapes unchecked.
  assert.deepEqual(paths("{src,../secrets}/**"), ["src", "../secrets"]);
});

test("literal path arguments are never truncated at glob characters", () => {
  const policy = { access: "write" as const, pathArguments: [required("path")] };

  assert.deepEqual(extractToolPaths({ path: "weird,name[1].ts" }, policy, "/cwd"), {
    ok: true,
    paths: ["weird,name[1].ts"],
  });
});

test("merging path arguments keeps the strictest requiredness and literalness", () => {
  const merged = mergeToolPolicies(
    { search: { access: "read", pathArguments: [{ name: "path", required: false, glob: true }] } },
    { search: { access: "read", pathArguments: [{ name: "path", required: true }] } },
  );

  assert.deepEqual(merged.search.pathArguments, [{ name: "path", required: true, glob: false }]);
});

test("configured tool paths resolve against the active session cwd", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-tool-policy-"));
  const workspace = join(root, "workspace");
  const target = join(root, "target");
  mkdirSync(workspace);
  mkdirSync(target);
  symlinkSync(target, join(workspace, "linked"));

  assert.equal(
    canonicalizeToolPath("linked/file.txt", workspace),
    join(realpathSync(target), "file.txt"),
  );
});

test("tool names cannot mutate policy object prototypes", () => {
  const parsed = parseToolPolicies(
    Object.fromEntries([
      ["__proto__", { access: "write", pathArguments: ["path"] }],
      ["constructor", { access: "read", pathArguments: ["path"] }],
    ]),
  );

  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "__proto__"), true);
  assert.equal(getToolPolicy(parsed, "__proto__")?.access, "write");
  assert.equal(getToolPolicy({}, "toString"), undefined);
  assert.equal(Object.prototype.hasOwnProperty.call(parsed, "constructor"), true);
});

test("policy merging keeps write access regardless of layer order", () => {
  const writeFirst = mergeToolPolicies(
    { copy: { access: "write", pathArguments: ["a"] } },
    { copy: { access: "read", pathArguments: ["b"] } },
  );
  const readOnly = mergeToolPolicies(
    { copy: { access: "read", pathArguments: ["a"] } },
    { copy: { access: "read", pathArguments: ["b"] } },
  );

  assert.equal(writeFirst.copy.access, "write");
  assert.deepEqual(writeFirst.copy.pathArguments, [required("a"), required("b")]);
  assert.equal(readOnly.copy.access, "read");
  assert.deepEqual(readOnly.copy.pathArguments, [required("a"), required("b")]);
});

test("policy parsing rejects malformed entries and non-record input", () => {
  assert.deepEqual(parseToolPolicies("nope"), {});
  assert.deepEqual(parseToolPolicies(["read"]), {});
  assert.deepEqual(
    parseToolPolicies({
      "": { access: "read", pathArguments: ["path"] },
      "   ": { access: "read", pathArguments: ["path"] },
      whitespaceArg: { access: "read", pathArguments: ["  "] },
      nonStringArg: { access: "read", pathArguments: [42] },
    }),
    {},
  );
});

test("path extraction deduplicates identical argument values", () => {
  const policy = {
    access: "write" as const,
    pathArguments: [required("source"), required("destination")],
  };

  assert.deepEqual(extractToolPaths({ source: "same", destination: "same" }, policy, "/cwd"), {
    ok: true,
    paths: ["same"],
  });
});

test("path arguments are rendered with their requiredness and glob handling", () => {
  assert.equal(formatToolPathArgument(required("path")), "path");
  assert.equal(formatToolPathArgument(optionalGlob("path")), "path:glob?");
});

test("canonicalizeToolPath handles tilde, absolute, and nonexistent paths", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-tool-policy-"));

  assert.equal(canonicalizeToolPath("~", root), realpathSync(homedir()));
  assert.equal(canonicalizeToolPath("/etc/hostname", root), realpathSync("/etc/hostname"));
  assert.equal(
    canonicalizeToolPath("does/not/exist.txt", root),
    join(realpathSync(root), "does", "not", "exist.txt"),
  );
});
