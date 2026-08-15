import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  addDomainToConfig,
  addReadPathToConfig,
  addWritePathToConfig,
  DEFAULT_CONFIG,
  DEFAULT_PERMISSION_PROMPT_TIMEOUT_SECONDS,
  getConfigPaths,
  loadConfig,
  mergeConfigLayers,
} from "../src/config.ts";

test("omitted permission prompt timeout defaults to ten minutes", () => {
  const merged = mergeConfigLayers(DEFAULT_CONFIG, {}, {});

  assert.equal(DEFAULT_PERMISSION_PROMPT_TIMEOUT_SECONDS, 600);
  assert.equal(merged.permissionPromptTimeoutSeconds, DEFAULT_PERMISSION_PROMPT_TIMEOUT_SECONDS);
});

test("mergeConfigLayers combines configured arrays and deduplicates entries", () => {
  const merged = mergeConfigLayers(
    DEFAULT_CONFIG,
    {
      network: {
        allowedDomains: ["global.example.com", "shared.example.com"],
        deniedDomains: ["blocked.example.com"],
        allowUnixSockets: ["/global.sock"],
      },
      filesystem: {
        askRead: ["/global-ask", "/shared-ask"],
        allowRead: ["/global", "/shared"],
        askWrite: ["global.prompt", "shared.prompt"],
        denyWrite: ["global.key"],
      },
    },
    {
      network: {
        allowedDomains: ["project.example.com", "shared.example.com"],
        deniedDomains: ["project-blocked.example.com"],
        allowUnixSockets: ["/project.sock"],
      },
      filesystem: {
        askRead: ["/project-ask", "/shared-ask"],
        allowRead: ["/project", "/shared"],
        askWrite: ["project.prompt", "shared.prompt"],
        denyWrite: ["project.key"],
      },
    },
  );

  assert.deepEqual(merged.network?.allowedDomains, [
    "global.example.com",
    "shared.example.com",
    "project.example.com",
  ]);
  assert.deepEqual(merged.network?.deniedDomains, [
    "blocked.example.com",
    "project-blocked.example.com",
  ]);
  assert.deepEqual(merged.network?.allowUnixSockets, ["/global.sock", "/project.sock"]);
  assert.deepEqual(merged.filesystem?.askRead, ["/global-ask", "/shared-ask", "/project-ask"]);
  assert.deepEqual(merged.filesystem?.allowRead, ["/global", "/shared", "/project"]);
  assert.deepEqual(merged.filesystem?.askWrite, [
    "global.prompt",
    "shared.prompt",
    "project.prompt",
  ]);
  assert.deepEqual(merged.filesystem?.denyWrite, [
    ...(DEFAULT_CONFIG.filesystem?.denyWrite ?? []),
    "global.key",
    "project.key",
  ]);
});

test("mergeConfigLayers ignores malformed permission arrays", () => {
  const merged = mergeConfigLayers(
    DEFAULT_CONFIG,
    {
      filesystem: {
        askRead: "secrets/**" as unknown as string[],
        askWrite: 42 as unknown as string[],
        denyWrite: "*.key" as unknown as string[],
      },
    },
    {},
  );

  assert.deepEqual(merged.filesystem?.askRead, DEFAULT_CONFIG.filesystem?.askRead);
  assert.deepEqual(merged.filesystem?.askWrite, DEFAULT_CONFIG.filesystem?.askWrite);
  assert.deepEqual(merged.filesystem?.denyWrite, DEFAULT_CONFIG.filesystem?.denyWrite);
});

test("deny lists are a floor: configuration can only add, never remove", () => {
  const merged = mergeConfigLayers(
    DEFAULT_CONFIG,
    { filesystem: { denyRead: [], denyWrite: [] } },
    { filesystem: { denyWrite: ["secrets/**"] } },
  );

  assert.deepEqual(merged.filesystem?.denyRead, DEFAULT_CONFIG.filesystem?.denyRead);
  assert.deepEqual(merged.filesystem?.denyWrite, [
    ...(DEFAULT_CONFIG.filesystem?.denyWrite ?? []),
    "secrets/**",
  ]);
});

test("mergeConfigLayers uses defaults only for arrays not configured by either file", () => {
  const merged = mergeConfigLayers(
    DEFAULT_CONFIG,
    {
      enabled: false,
      permissionPromptTimeoutSeconds: 30,
      filesystem: { allowWrite: [] },
    },
    {
      enabled: true,
      permissionPromptTimeoutSeconds: 0,
      allowBrowserProcess: true,
    },
  );

  assert.equal(merged.enabled, true);
  assert.equal(merged.permissionPromptTimeoutSeconds, 0);
  assert.equal(merged.allowBrowserProcess, true);
  assert.deepEqual(merged.filesystem?.allowWrite, []);
  assert.deepEqual(merged.filesystem?.allowRead, DEFAULT_CONFIG.filesystem?.allowRead);
  assert.deepEqual(merged.network?.allowedDomains, DEFAULT_CONFIG.network?.allowedDomains);
});

test("getConfigPaths uses Pi's configured agent directory", () => {
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = "/tmp/custom-pi-agent";
  try {
    assert.deepEqual(getConfigPaths("/workspace"), {
      globalPath: "/tmp/custom-pi-agent/sandbox.json",
      projectPath: "/workspace/.pi/sandbox.json",
    });
  } finally {
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
  }
});

test("permission writers only persist the property being changed", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-config-"));
  const configPath = join(root, "sandbox.json");

  addReadPathToConfig(configPath, "/read");
  addWritePathToConfig(configPath, "/write");
  addDomainToConfig(configPath, "example.com");

  const written = JSON.parse(readFileSync(configPath, "utf8"));
  assert.deepEqual(written, {
    network: { allowedDomains: ["example.com"] },
    filesystem: {
      allowRead: ["/read"],
      allowWrite: ["/write"],
    },
  });
});

test("configured tool policies are additive to built-in policies", () => {
  const merged = mergeConfigLayers(
    DEFAULT_CONFIG,
    {
      toolPolicies: {
        replace: { access: "write", pathArguments: ["path"] },
      },
    },
    {
      toolPolicies: {
        undo_last_replace: { access: "write", pathArguments: ["path"] },
      },
    },
  );

  assert.deepEqual(merged.toolPolicies, {
    read: { access: "read", pathArguments: ["path"] },
    write: { access: "write", pathArguments: ["path"] },
    edit: { access: "write", pathArguments: ["path"] },
    replace: { access: "write", pathArguments: ["path"] },
    undo_last_replace: { access: "write", pathArguments: ["path"] },
  });
});

test("getConfigPaths reports the global config file that loadConfig actually protects", () => {
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-agent-"));
  const projectDir = mkdtempSync(join(tmpdir(), "pi-sandbox-project-"));
  const previous = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;

  try {
    const { globalPath, projectPath } = getConfigPaths(projectDir);
    assert.equal(globalPath, join(agentDir, "sandbox.json"));

    // The reported paths must be the ones write-protected by loadConfig,
    // otherwise "allow globally" writes to a file that is never read.
    const denyWrite = loadConfig(projectDir).filesystem?.denyWrite ?? [];
    assert.ok(denyWrite.includes(globalPath));
    assert.ok(denyWrite.includes(projectPath));
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
  }
});
