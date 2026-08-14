import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import extension from "../src/extension.ts";

// Handler-level integration test: loads the real extension with a mock pi API,
// boots real sessions (initializing the real OS sandbox), and fires synthetic
// tool_call events to verify the enforcement wiring end to end.
// Headless context (hasUI: false) makes every permission prompt auto-abort,
// so any path requiring a prompt results in a block.

type Handler = (event: any, ctx: any) => Promise<any>;

const handlers = new Map<string, Handler>();
const notifications: string[] = [];
const pi = {
  registerFlag: () => {},
  getFlag: () => false,
  registerTool: () => {},
  registerShortcut: () => {},
  registerCommand: () => {},
  on: (name: string, handler: Handler) => handlers.set(name, handler),
  events: { emit: () => {} },
};

extension(pi as any);

function makeCtx(cwd: string) {
  return {
    cwd,
    hasUI: false,
    ui: {
      setStatus: () => {},
      notify: (message: string) => notifications.push(message),
      theme: { fg: (_color: string, text: string) => text },
    },
  };
}

function makeProject(name: string, config: object): string {
  const dir = mkdtempSync(join(tmpdir(), `pi-sandbox-hook-${name}-`));
  mkdirSync(join(dir, ".pi"), { recursive: true });
  writeFileSync(join(dir, ".pi", "sandbox.json"), JSON.stringify(config, null, 2));
  writeFileSync(join(dir, "inside.txt"), "hello");
  return dir;
}

const baseFs = {
  denyRead: ["/Users", "/home"],
  allowRead: ["."],
  allowWrite: [".", "/tmp"],
  denyWrite: [".env", ".env.*", "*.pem", "*.key"],
};

// Project A: built-in policies only (read/write/edit on "path").
const projA = makeProject("a", { enabled: true, filesystem: baseFs });
// Project B: read overridden to a "file" argument, bash given a policy that must
// be ignored, and a custom multi-path tool.
const projB = makeProject("b", {
  enabled: true,
  filesystem: baseFs,
  toolPolicies: {
    read: { access: "read", pathArguments: ["file"] },
    bash: { access: "write", pathArguments: ["command"] },
    mcp_move: { access: "write", pathArguments: ["source", "destination"] },
  },
});

let sandboxActive = false;

function toolCall(cwd: string, toolName: string, input: Record<string, unknown>) {
  return handlers.get("tool_call")!({ toolName, input }, makeCtx(cwd));
}

test("setup: real sessions boot with the OS sandbox", async () => {
  const sessionStart = handlers.get("session_start")!;
  await sessionStart({}, makeCtx(projA));
  await sessionStart({}, makeCtx(projB));
  sandboxActive = !notifications.some((message) =>
    message.includes("Sandbox initialization failed"),
  );
});

function skipIfInactive(t: import("node:test").TestContext) {
  if (!sandboxActive) t.skip("OS-level sandbox unavailable on this machine");
}

test("read inside allowRead is allowed", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  assert.equal(await toolCall(projA, "read", { path: "inside.txt" }), undefined);
});

test("read outside allowances is blocked (headless prompt aborts)", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const result = await toolCall(projA, "read", { path: "/etc/hostname" });
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /read access denied/);
});

test("a throwing prompt UI fails closed", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const ctx = {
    ...makeCtx(projA),
    hasUI: true,
    ui: {
      ...makeCtx(projA).ui,
      custom: () => {
        throw new Error("ui exploded");
      },
    },
  };
  const result = await handlers.get("tool_call")!(
    { toolName: "read", input: { path: "/etc/hostname" } },
    ctx,
  );
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /fail-closed/);
});

test("write inside allowWrite is allowed", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  assert.equal(await toolCall(projA, "write", { path: "newfile.txt" }), undefined);
});

test("write to a denyWrite path is a hard block", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const result = await toolCall(projA, "write", { path: ".env" });
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /denyWrite/);
});

test("the sandbox config file itself is write-protected", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const result = await toolCall(projA, "write", {
    path: join(".pi", "sandbox.json"),
  });
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /denyWrite/);
});

test("edit escaping the project is blocked", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const result = await toolCall(projA, "edit", {
    path: join(homedir(), "pi-sandbox-hook-outside.txt"),
  });
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /not in allowWrite/);
});

test("empty path argument fails closed", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  const result = await toolCall(projA, "write", { path: "" });
  assert.equal(result?.block, true);
});

test("tools without a configured policy are untouched", async (t) => {
  skipIfInactive(t);
  process.chdir(projA);
  assert.equal(await toolCall(projA, "unknown_tool", { path: "/etc/hostname" }), undefined);
});

test("configured path arguments replace the built-in default", async (t) => {
  skipIfInactive(t);
  process.chdir(projB);
  assert.equal(await toolCall(projB, "read", { file: "inside.txt" }), undefined);
  const result = await toolCall(projB, "read", { path: "inside.txt" });
  assert.equal(result?.block, true);
  assert.match(result?.reason ?? "", /"file"/);
});

test("a policy for bash is ignored; the OS sandbox owns bash", async (t) => {
  skipIfInactive(t);
  process.chdir(projB);
  assert.equal(await toolCall(projB, "bash", { command: "echo hello" }), undefined);
});

test("custom multi-path tool checks every path argument", async (t) => {
  skipIfInactive(t);
  process.chdir(projB);
  assert.equal(
    await toolCall(projB, "mcp_move", { source: "inside.txt", destination: "moved.txt" }),
    undefined,
  );

  const outside = await toolCall(projB, "mcp_move", {
    source: "inside.txt",
    destination: "/etc/evil.txt",
  });
  assert.equal(outside?.block, true);
  assert.match(outside?.reason ?? "", /not in allowWrite/);

  const denied = await toolCall(projB, "mcp_move", {
    source: "inside.txt",
    destination: ".env",
  });
  assert.equal(denied?.block, true);
  assert.match(denied?.reason ?? "", /denyWrite/);
});

test("cleanup: sandbox shuts down", async () => {
  await handlers.get("session_shutdown")?.({}, makeCtx(projA));
});
