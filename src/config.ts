import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { type SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

import { BUILTIN_TOOL_POLICIES, mergeToolPolicies, type ToolPolicies } from "./tool-policy.ts";

type RuntimeFilesystemConfig = NonNullable<SandboxRuntimeConfig["filesystem"]>;

export type FilesystemConfig = RuntimeFilesystemConfig & {
  /** Paths that configured read tools must ask about before execution. */
  askRead?: string[];
  /** Paths that configured write tools must ask about before execution. */
  askWrite?: string[];
};

export type SandboxConfig = Omit<SandboxRuntimeConfig, "network" | "filesystem"> & {
  enabled?: boolean;
  permissionPromptTimeoutSeconds?: number;
  network?: NonNullable<SandboxRuntimeConfig["network"]> & {
    allowUnauthenticatedSocksProxy?: boolean;
    /** Route ordinary `ssh` commands through the sandbox SOCKS proxy. */
    sshProxy?: boolean;
  };
  filesystem?: FilesystemConfig;
  toolPolicies?: ToolPolicies;
};

type NetworkConfig = NonNullable<SandboxConfig["network"]>;

export type SandboxConfigFile = Omit<Partial<SandboxConfig>, "network" | "filesystem"> & {
  network?: Partial<NetworkConfig>;
  filesystem?: Partial<FilesystemConfig>;
};

export const DEFAULT_PERMISSION_PROMPT_TIMEOUT_SECONDS = 10 * 60;

export const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  permissionPromptTimeoutSeconds: DEFAULT_PERMISSION_PROMPT_TIMEOUT_SECONDS,
  network: {
    allowUnauthenticatedSocksProxy: process.platform === "darwin",
    sshProxy: true,
    allowedDomains: [],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: [],
    askRead: [],
    allowRead: ["."],
    allowWrite: ["."],
    askWrite: [],
    denyWrite: [],
  },
  toolPolicies: BUILTIN_TOOL_POLICIES,
};

function mergeObjects(base: SandboxConfig, overrides: SandboxConfigFile): SandboxConfig {
  return {
    ...base,
    ...overrides,
    network: overrides.network
      ? ({ ...base.network, ...overrides.network } as NetworkConfig)
      : base.network,
    filesystem: overrides.filesystem
      ? ({ ...base.filesystem, ...overrides.filesystem } as FilesystemConfig)
      : base.filesystem,
  };
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value;
}

function mergeConfiguredArray(
  fallback: string[] | undefined,
  globalValue: unknown,
  projectValue: unknown,
): string[] | undefined {
  const globalEntries = stringArray(globalValue);
  const projectEntries = stringArray(projectValue);
  if (globalEntries === undefined && projectEntries === undefined) return fallback;
  return [...new Set([...(globalEntries ?? []), ...(projectEntries ?? [])])];
}

export function mergeConfigLayers(
  defaults: SandboxConfig,
  globalConfig: SandboxConfigFile,
  projectConfig: SandboxConfigFile,
): SandboxConfig {
  const merged = mergeObjects(mergeObjects(defaults, globalConfig), projectConfig);

  return {
    ...merged,
    toolPolicies: mergeToolPolicies(
      defaults.toolPolicies,
      globalConfig.toolPolicies,
      projectConfig.toolPolicies,
    ),
    network: {
      ...merged.network,
      allowedDomains:
        mergeConfiguredArray(
          defaults.network?.allowedDomains,
          globalConfig.network?.allowedDomains,
          projectConfig.network?.allowedDomains,
        ) ?? [],
      deniedDomains:
        mergeConfiguredArray(
          defaults.network?.deniedDomains,
          globalConfig.network?.deniedDomains,
          projectConfig.network?.deniedDomains,
        ) ?? [],
      allowUnixSockets: mergeConfiguredArray(
        defaults.network?.allowUnixSockets,
        globalConfig.network?.allowUnixSockets,
        projectConfig.network?.allowUnixSockets,
      ),
      allowMachLookup: mergeConfiguredArray(
        defaults.network?.allowMachLookup,
        globalConfig.network?.allowMachLookup,
        projectConfig.network?.allowMachLookup,
      ),
    },
    filesystem: {
      ...merged.filesystem,
      // Deny lists are a security floor: built-in defaults always apply and
      // configuration can only add entries, never remove them.
      denyRead: [
        ...new Set([
          ...(defaults.filesystem?.denyRead ?? []),
          ...(mergeConfiguredArray(
            [],
            globalConfig.filesystem?.denyRead,
            projectConfig.filesystem?.denyRead,
          ) ?? []),
        ]),
      ],
      askRead:
        mergeConfiguredArray(
          defaults.filesystem?.askRead,
          globalConfig.filesystem?.askRead,
          projectConfig.filesystem?.askRead,
        ) ?? [],
      allowRead: mergeConfiguredArray(
        defaults.filesystem?.allowRead,
        globalConfig.filesystem?.allowRead,
        projectConfig.filesystem?.allowRead,
      ),
      askWrite:
        mergeConfiguredArray(
          defaults.filesystem?.askWrite,
          globalConfig.filesystem?.askWrite,
          projectConfig.filesystem?.askWrite,
        ) ?? [],
      allowWrite:
        mergeConfiguredArray(
          defaults.filesystem?.allowWrite,
          globalConfig.filesystem?.allowWrite,
          projectConfig.filesystem?.allowWrite,
        ) ?? [],
      denyWrite: [
        ...new Set([
          ...(defaults.filesystem?.denyWrite ?? []),
          ...(mergeConfiguredArray(
            [],
            globalConfig.filesystem?.denyWrite,
            projectConfig.filesystem?.denyWrite,
          ) ?? []),
        ]),
      ],
    },
  };
}
const warnedInvalidPermissionTimeouts = new Set<string>();

function isValidPermissionPromptTimeout(value: unknown): boolean {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function readJsonConfig(configPath: string, warn: boolean): SandboxConfigFile {
  if (!existsSync(configPath)) return {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(configPath, "utf-8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("configuration must be a JSON object");
    }
    const config = parsed as SandboxConfigFile;
    const timeout = config.permissionPromptTimeoutSeconds;
    if (timeout !== undefined && !isValidPermissionPromptTimeout(timeout)) {
      const warningKey = `${configPath}:${String(timeout)}`;
      if (!warnedInvalidPermissionTimeouts.has(warningKey)) {
        warnedInvalidPermissionTimeouts.add(warningKey);
        console.error(
          `Warning: Invalid permissionPromptTimeoutSeconds in ${configPath}: expected a finite number >= 0; using the default`,
        );
      }
      delete config.permissionPromptTimeoutSeconds;
    }
    return config;
  } catch (error) {
    if (warn) console.error(`Warning: Could not parse ${configPath}: ${error}`);
    return {};
  }
}

export function getConfigPaths(cwd: string): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(getAgentDir(), "sandbox.json"),
    projectPath: join(cwd, ".pi", "sandbox.json"),
  };
}

export function loadConfig(cwd: string): SandboxConfig {
  const { globalPath, projectPath } = getConfigPaths(cwd);
  const globalConfig = readJsonConfig(globalPath, true);
  const projectConfig = readJsonConfig(projectPath, true);
  const merged = mergeConfigLayers(DEFAULT_CONFIG, globalConfig, projectConfig);

  return {
    ...merged,
    filesystem: {
      ...merged.filesystem,
      denyRead: merged.filesystem?.denyRead ?? [],
      allowWrite: merged.filesystem?.allowWrite ?? [],
      // The config files themselves are always write-protected: loadConfig is
      // re-evaluated on every tool call, so a writable config would let the
      // agent disable its own enforcement mid-session.
      denyWrite: [...new Set([...(merged.filesystem?.denyWrite ?? []), globalPath, projectPath])],
    },
  };
}

function writeConfigFile(configPath: string, config: SandboxConfigFile): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

export function addDomainToConfig(configPath: string, domain: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = stringArray(config.network?.allowedDomains) ?? [];
  if (existing.includes(domain)) return;

  config.network = {
    ...config.network,
    allowedDomains: [...existing, domain],
  };
  writeConfigFile(configPath, config);
}

export function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = stringArray(config.filesystem?.allowRead) ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowRead: [...existing, pathToAdd],
  };
  writeConfigFile(configPath, config);
}

export function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = stringArray(config.filesystem?.allowWrite) ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowWrite: [...existing, pathToAdd],
  };
  writeConfigFile(configPath, config);
}
