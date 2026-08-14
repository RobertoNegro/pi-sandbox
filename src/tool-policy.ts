import { canonicalizePath } from "./policy.ts";

export type ToolAccess = "read" | "write";

export interface ToolPolicy {
  access: ToolAccess;
  pathArguments: string[];
}

export type ToolPolicies = Record<string, ToolPolicy>;

export const BUILTIN_TOOL_POLICIES: ToolPolicies = {
  read: { access: "read", pathArguments: ["path"] },
  write: { access: "write", pathArguments: ["path"] },
  edit: { access: "write", pathArguments: ["path"] },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parsePolicy(value: unknown): ToolPolicy | undefined {
  if (!isRecord(value)) return undefined;
  if (value.access !== "read" && value.access !== "write") return undefined;
  if (
    !Array.isArray(value.pathArguments) ||
    value.pathArguments.length === 0 ||
    !value.pathArguments.every(
      (argument) => typeof argument === "string" && argument.trim().length > 0,
    )
  ) {
    return undefined;
  }

  return {
    access: value.access,
    pathArguments: [...new Set(value.pathArguments)],
  };
}

export function parseToolPolicies(value: unknown): ToolPolicies {
  if (!isRecord(value)) return {};

  const policies: Array<[string, ToolPolicy]> = [];
  for (const [toolName, rawPolicy] of Object.entries(value)) {
    if (toolName.trim().length === 0) continue;
    const policy = parsePolicy(rawPolicy);
    if (policy) policies.push([toolName, policy]);
  }
  return Object.fromEntries(policies);
}

function mergePolicy(left: ToolPolicy, right: ToolPolicy, replacePaths: boolean): ToolPolicy {
  return {
    access: left.access === "write" || right.access === "write" ? "write" : "read",
    pathArguments: replacePaths
      ? right.pathArguments
      : [...new Set([...left.pathArguments, ...right.pathArguments])],
  };
}

export function mergeToolPolicies(...layers: unknown[]): ToolPolicies {
  const merged = new Map<string, ToolPolicy>();

  for (const layer of layers) {
    for (const [toolName, policy] of Object.entries(parseToolPolicies(layer))) {
      const existing = merged.get(toolName);
      // Built-in tools have a single "path" argument; a configured policy for a
      // built-in tool replaces its path arguments instead of unioning, otherwise
      // every call would fail extraction on the missing built-in argument.
      const isBuiltin = Object.prototype.hasOwnProperty.call(BUILTIN_TOOL_POLICIES, toolName);
      merged.set(toolName, existing ? mergePolicy(existing, policy, isBuiltin) : policy);
    }
  }

  return Object.fromEntries(merged);
}

export function getToolPolicy(
  policies: ToolPolicies | undefined,
  toolName: string,
): ToolPolicy | undefined {
  return policies && Object.prototype.hasOwnProperty.call(policies, toolName)
    ? policies[toolName]
    : undefined;
}

export type ToolPathExtraction = { ok: true; paths: string[] } | { ok: false; reason: string };

export function extractToolPaths(
  input: Record<string, unknown>,
  policy: ToolPolicy,
): ToolPathExtraction {
  const paths: string[] = [];

  for (const argument of policy.pathArguments) {
    const value = input[argument];
    if (typeof value !== "string" || value.trim().length === 0) {
      return {
        ok: false,
        reason: `path argument "${argument}" must be a non-empty string`,
      };
    }
    if (value.includes("\0")) {
      return {
        ok: false,
        reason: `path argument "${argument}" must not contain NUL bytes`,
      };
    }
    paths.push(value);
  }

  return { ok: true, paths: [...new Set(paths)] };
}

export function canonicalizeToolPath(inputPath: string, cwd: string): string {
  return canonicalizePath(inputPath, cwd);
}
