import { canonicalizePath } from "./policy.ts";

export type ToolAccess = "read" | "write";

export interface ToolPathArgument {
  name: string;
  /** When false, a missing or empty value falls back to the session cwd. */
  required: boolean;
  /** When true, the value is a glob (or comma-separated glob list), not a literal path. */
  glob: boolean;
}

export interface ToolPolicy {
  access: ToolAccess;
  pathArguments: ToolPathArgument[];
}

export type ToolPolicies = Record<string, ToolPolicy>;

/** Loose shape accepted in config files, before normalization. */
export type ToolPathArgumentFile = string | { name: string; required?: boolean; glob?: boolean };

export interface ToolPolicyFile {
  access: ToolAccess;
  pathArguments: ToolPathArgumentFile[];
}

export type ToolPoliciesFile = Record<string, ToolPolicyFile>;

export const BUILTIN_TOOL_POLICIES: ToolPolicies = {
  read: { access: "read", pathArguments: [{ name: "path", required: true, glob: false }] },
  write: { access: "write", pathArguments: [{ name: "path", required: true, glob: false }] },
  edit: { access: "write", pathArguments: [{ name: "path", required: true, glob: false }] },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parsePathArgument(value: unknown): ToolPathArgument | undefined {
  if (typeof value === "string") {
    return value.trim().length > 0 ? { name: value, required: true, glob: false } : undefined;
  }
  if (!isRecord(value)) return undefined;
  if (typeof value.name !== "string" || value.name.trim().length === 0) return undefined;
  if (value.required !== undefined && typeof value.required !== "boolean") return undefined;
  if (value.glob !== undefined && typeof value.glob !== "boolean") return undefined;

  return {
    name: value.name,
    required: value.required ?? true,
    glob: value.glob ?? false,
  };
}

function dedupeArguments(argumentList: ToolPathArgument[]): ToolPathArgument[] {
  const byName = new Map<string, ToolPathArgument>();
  for (const argument of argumentList) {
    const existing = byName.get(argument.name);
    byName.set(argument.name, existing ? mergeArgument(existing, argument) : argument);
  }
  return [...byName.values()];
}

function parsePolicy(value: unknown): ToolPolicy | undefined {
  if (!isRecord(value)) return undefined;
  if (value.access !== "read" && value.access !== "write") return undefined;
  if (!Array.isArray(value.pathArguments) || value.pathArguments.length === 0) return undefined;

  const parsed: ToolPathArgument[] = [];
  for (const rawArgument of value.pathArguments) {
    const argument = parsePathArgument(rawArgument);
    // A single malformed argument would silently narrow the checked paths, so
    // the whole policy is rejected instead.
    if (!argument) return undefined;
    parsed.push(argument);
  }

  return { access: value.access, pathArguments: dedupeArguments(parsed) };
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

function mergeArgument(left: ToolPathArgument, right: ToolPathArgument): ToolPathArgument {
  return {
    name: left.name,
    // Stricter wins: "required" blocks a call with a missing value, and a
    // literal path is checked verbatim instead of truncated to a glob prefix.
    required: left.required || right.required,
    glob: left.glob && right.glob,
  };
}

function mergePolicy(left: ToolPolicy, right: ToolPolicy, replacePaths: boolean): ToolPolicy {
  return {
    access: left.access === "write" || right.access === "write" ? "write" : "read",
    pathArguments: replacePaths
      ? right.pathArguments
      : dedupeArguments([...left.pathArguments, ...right.pathArguments]),
  };
}

export function mergeToolPolicies(...layers: unknown[]): ToolPolicies {
  const merged = new Map<string, ToolPolicy>();

  for (const layer of layers) {
    for (const [toolName, policy] of Object.entries(parseToolPolicies(layer))) {
      const existing = merged.get(toolName);
      // Built-in tools have known path arguments; a configured policy for a
      // built-in tool replaces them instead of unioning, otherwise every call
      // would fail extraction on the missing built-in argument.
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

export function formatToolPathArgument(argument: ToolPathArgument): string {
  return `${argument.name}${argument.glob ? ":glob" : ""}${argument.required ? "" : "?"}`;
}

const GLOB_CHARACTERS = /[*?[\]]/;

/**
 * Longest literal path prefix of a glob: everything before the first segment
 * that contains a wildcard. A glob can never escape that prefix, so checking it
 * covers every file the pattern can reach.
 */
function globLiteralPrefix(pattern: string): string {
  const segments = pattern.replace(/[{}]/g, "").split("/");
  const wildcard = segments.findIndex((segment) => GLOB_CHARACTERS.test(segment));
  const literal = (wildcard === -1 ? segments : segments.slice(0, wildcard)).join("/");
  return literal.length > 0 ? literal : ".";
}

/**
 * Glob arguments accept comma-separated lists and brace alternations; every
 * alternative is checked separately so one of them cannot smuggle in a path
 * outside the allowed roots.
 */
function expandGlobArgument(value: string): string[] {
  const expanded = value
    .split(",")
    .map((pattern) => pattern.trim())
    .filter((pattern) => pattern.length > 0)
    .map(globLiteralPrefix);
  return expanded.length > 0 ? expanded : ["."];
}

export type ToolPathExtraction = { ok: true; paths: string[] } | { ok: false; reason: string };

export function extractToolPaths(
  input: Record<string, unknown>,
  policy: ToolPolicy,
  cwd: string,
): ToolPathExtraction {
  const paths: string[] = [];

  for (const argument of policy.pathArguments) {
    const value = input[argument.name];
    if (typeof value !== "string" || value.trim().length === 0) {
      if (argument.required) {
        return {
          ok: false,
          reason: `path argument "${argument.name}" must be a non-empty string`,
        };
      }
      // An omitted optional path means the tool operates on the session cwd,
      // so that is what gets authorized: the call is never left unchecked.
      paths.push(cwd);
      continue;
    }
    if (value.includes("\0")) {
      return {
        ok: false,
        reason: `path argument "${argument.name}" must not contain NUL bytes`,
      };
    }
    if (argument.glob) {
      paths.push(...expandGlobArgument(value));
      continue;
    }
    paths.push(value);
  }

  return { ok: true, paths: [...new Set(paths)] };
}

export function canonicalizeToolPath(inputPath: string, cwd: string): string {
  return canonicalizePath(inputPath, cwd);
}
