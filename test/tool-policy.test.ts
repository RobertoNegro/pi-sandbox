import { mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  BUILTIN_TOOL_POLICIES,
  canonicalizeToolPath,
  extractToolPaths,
  getToolPolicy,
  mergeToolPolicies,
  parseToolPolicies,
} from "../src/tool-policy.ts";

test("conflicting policies merge to the stricter write access and require every path", () => {
  const merged = mergeToolPolicies(
    { copy: { access: "read", pathArguments: ["source"] } },
    { copy: { access: "write", pathArguments: ["destination"] } },
  );

  assert.deepEqual(merged.copy, {
    access: "write",
    pathArguments: ["source", "destination"],
  });
});

test("configured policies for built-in tools replace path arguments instead of unioning", () => {
  const merged = mergeToolPolicies(BUILTIN_TOOL_POLICIES, {
    read: { access: "read", pathArguments: ["file"] },
    write: { access: "write", pathArguments: ["target"] },
  });

  assert.deepEqual(merged.read, { access: "read", pathArguments: ["file"] });
  assert.deepEqual(merged.write, { access: "write", pathArguments: ["target"] });
  assert.deepEqual(merged.edit, { access: "write", pathArguments: ["path"] });
});

test("malformed policies are ignored without removing valid policy layers", () => {
  const parsed = parseToolPolicies({
    valid: { access: "write", pathArguments: ["path", "path"] },
    noPaths: { access: "write", pathArguments: [] },
    wrongAccess: { access: "execute", pathArguments: ["path"] },
    wrongShape: "path",
  });

  assert.deepEqual(parsed, {
    valid: { access: "write", pathArguments: ["path"] },
  });

  const merged = mergeToolPolicies(
    { replace: { access: "write", pathArguments: ["path"] } },
    { replace: { access: "write", pathArguments: [] } },
  );
  assert.deepEqual(merged.replace, { access: "write", pathArguments: ["path"] });
});

test("path extraction checks every configured argument and fails closed", () => {
  const policy = { access: "write" as const, pathArguments: ["source", "destination"] };

  assert.deepEqual(extractToolPaths({ source: "a", destination: "b" }, policy), {
    ok: true,
    paths: ["a", "b"],
  });
  assert.deepEqual(extractToolPaths({ source: "a" }, policy), {
    ok: false,
    reason: 'path argument "destination" must be a non-empty string',
  });
  assert.deepEqual(extractToolPaths({ source: "a", destination: "\0bad" }, policy), {
    ok: false,
    reason: 'path argument "destination" must not contain NUL bytes',
  });
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
  assert.deepEqual(writeFirst.copy.pathArguments, ["a", "b"]);
  assert.equal(readOnly.copy.access, "read");
  assert.deepEqual(readOnly.copy.pathArguments, ["a", "b"]);
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
  const policy = { access: "write" as const, pathArguments: ["source", "destination"] };

  assert.deepEqual(extractToolPaths({ source: "same", destination: "same" }, policy), {
    ok: true,
    paths: ["same"],
  });
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
