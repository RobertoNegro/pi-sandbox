import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, resolve } from "node:path";

export function decideWritePolicy(
  path: string,
  allowWrite: string[],
  denyWrite: string[],
  cwd: string = process.cwd(),
) {
  if (matchesPattern(path, denyWrite, cwd)) return "deny";
  if (allowWrite.length === 0 || !matchesPattern(path, allowWrite, cwd)) return "prompt";
  return "allow";
}

export async function resolveWritePermission({
  path,
  allowWrite,
  denyWrite,
  cwd,
  prompt,
  saveWritePermission,
}: {
  path: string;
  allowWrite: string[];
  denyWrite: string[];
  cwd?: string;
  prompt: (path: string) => Promise<{
    action: "abort" | "session" | "project" | "global";
    value: string;
  }>;
  saveWritePermission: (choice: "session" | "project" | "global", value: string) => Promise<void>;
}) {
  const policy = decideWritePolicy(path, allowWrite, denyWrite, cwd);
  if (policy !== "prompt") return { action: policy };

  const choice = await prompt(path);
  if (choice.action === "abort") return { action: "abort", value: choice.value };

  await saveWritePermission(choice.action, choice.value);
  return { action: "granted", value: choice.value };
}

export function findExplicitAskRule(
  path: string,
  askRules: string[],
  approvedRules: string[],
  matches: (path: string, patterns: string[]) => boolean,
): string | undefined {
  const matchingRules = askRules.filter((rule) => matches(path, [rule]));
  const specificity = (rule: string): number =>
    rule.replaceAll("*", "").replaceAll("?", "").replaceAll("[", "").replaceAll("]", "").length;
  matchingRules.sort((left, right) => specificity(right) - specificity(left));

  const rule = matchingRules[0];
  return rule !== undefined && !approvedRules.includes(rule) ? rule : undefined;
}

export function unsupportedLinuxDenyWritePatterns(patterns: string[]): string[] {
  return patterns.filter((pattern) => {
    // A trailing /** is supported as recursive directory access: sandbox-runtime
    // strips the suffix before giving the concrete directory to bubblewrap.
    const withoutRecursiveSuffix = pattern.replace(/\/\*\*$/, "");
    return ["*", "?", "[", "]"].some((character) => withoutRecursiveSuffix.includes(character));
  });
}

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) domains.add(match[1]);
  return [...domains];
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

export function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

export function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((pattern) => domainMatchesPattern(domain, pattern));
}

function expandPath(filePath: string, cwd: string = process.cwd()): string {
  return resolve(cwd, filePath.replace(/^~(?=$|\/)/, homedir()));
}

export function canonicalizePath(filePath: string, cwd: string = process.cwd()): string {
  const absolutePath = expandPath(filePath, cwd);
  try {
    return realpathSync.native(absolutePath);
  } catch {
    const tail: string[] = [];
    let probe = absolutePath;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return absolutePath;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolutePath;
    }
  }
}

export function matchesPattern(
  filePath: string,
  patterns: string[],
  cwd: string = process.cwd(),
): boolean {
  // macOS APFS is case-insensitive by default: fold case so that e.g. a write
  // to ".ENV" still matches the ".env" deny pattern. realpathSync preserves the
  // on-disk case of existing files and the input case of nonexistent ones, so
  // canonicalization alone does not normalize case.
  const fold = (value: string) => (process.platform === "darwin" ? value.toLowerCase() : value);
  const absolutePath = fold(canonicalizePath(filePath, cwd));
  return patterns.some((pattern) => {
    const absolutePattern = fold(
      pattern.includes("*") ? expandPath(pattern, cwd) : canonicalizePath(pattern, cwd),
    );
    if (pattern.includes("*")) {
      const escaped = absolutePattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      return new RegExp(`^${escaped}$`).test(absolutePath);
    }
    const separator = absolutePattern.endsWith("/") ? "" : "/";
    return absolutePath === absolutePattern || absolutePath.startsWith(absolutePattern + separator);
  });
}
