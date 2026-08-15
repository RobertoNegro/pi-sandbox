import { SandboxManager } from "@carderne/sandbox-runtime";
import {
  createBashToolDefinition,
  isToolCallEventType,
  SettingsManager,
  type AgentToolResult,
  type ExtensionAPI,
  type ExtensionContext,
  type ToolCallEvent,
  type ToolCallEventResult,
} from "@earendil-works/pi-coding-agent";
import { Key } from "@earendil-works/pi-tui";

import {
  addDomainToConfig,
  addReadPathToConfig,
  addWritePathToConfig,
  getConfigPaths,
  loadConfig,
  type SandboxConfig,
} from "./config.ts";
import {
  canonicalizePath,
  domainIsAllowed,
  extractDomainsFromCommand,
  findExplicitAskRule,
  matchesPattern,
  resolveWritePermission,
  unsupportedLinuxDenyWritePatterns,
} from "./policy.ts";
import {
  createSandboxedBashOps,
  extractBlockedWritePath,
  initializeSandbox,
  reinitializeSandbox,
  resolveAllowances,
  type EffectiveAllowances,
  type SessionAllowances,
  supportsNodeEnvProxy,
} from "./sandbox-runtime.ts";
import {
  canonicalizeToolPath,
  extractToolPaths,
  getToolPolicy,
  type ToolAccess,
} from "./tool-policy.ts";
import {
  formatSandboxConfiguration,
  formatSandboxStatus,
  type PermissionPromptResult,
  promptDomainBlock,
  promptReadBlock,
  showPermissionPrompt,
  promptWriteBlock,
  warnIfAllDomainsAllowed,
} from "./ui.ts";

export default function (pi: ExtensionAPI) {
  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  const localCwd = process.cwd();
  const userShellPath = SettingsManager.create(localCwd).getShellPath();
  const localBash = createBashToolDefinition(localCwd, { shellPath: userShellPath });

  let sandboxEnabled = false;
  let sandboxInitialized = false;
  let toolPolicyState: "pending" | "active" | "disabled" | "unavailable" = "pending";
  const allowances: SessionAllowances = { domains: [], readPaths: [], writePaths: [] };

  const effectiveAllowances = (cwd: string) => resolveAllowances(loadConfig(cwd), allowances);
  const effectiveDomains = (cwd: string) => effectiveAllowances(cwd).domains;

  async function refreshSandbox(cwd: string): Promise<void> {
    if (!sandboxInitialized) return;
    try {
      await reinitializeSandbox(loadConfig(cwd), allowances);
    } catch (error) {
      console.error(`Warning: Failed to reinitialize sandbox: ${error}`);
    }
  }

  async function applyChoice(
    choice: Exclude<PermissionPromptResult["action"], "abort">,
    kind: "domain" | "read" | "write",
    value: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    const target = choice === "project" ? projectPath : globalPath;

    if (kind === "domain") {
      if (!allowances.domains.includes(value)) allowances.domains.push(value);
      if (choice !== "session") addDomainToConfig(target, value);
    } else if (kind === "read") {
      if (!allowances.readPaths.includes(value)) allowances.readPaths.push(value);
      if (choice !== "session") addReadPathToConfig(target, value);
    } else {
      if (!allowances.writePaths.includes(value)) allowances.writePaths.push(value);
      if (choice !== "session") addWritePathToConfig(target, value);
    }
    await refreshSandbox(cwd);
  }
  async function authorizeToolPath(
    access: ToolAccess,
    path: string,
    config: SandboxConfig,
    effective: EffectiveAllowances,
    ctx: ExtensionContext,
    refreshEffectiveAllowances: () => void,
  ): Promise<ToolCallEventResult | undefined> {
    const isRead = access === "read";
    const askRule = findExplicitAskRule(
      path,
      (isRead ? config.filesystem?.askRead : config.filesystem?.askWrite) ?? [],
      isRead ? effective.readPaths : effective.writePaths,
      (target, patterns) => matchesPattern(target, patterns, ctx.cwd),
    );
    const prompt = isRead ? promptReadBlock : promptWriteBlock;

    if (askRule) {
      const choice = await prompt(pi, ctx, path, config.permissionPromptTimeoutSeconds, askRule);
      if (choice.action === "abort") {
        return {
          block: true,
          reason: `Sandbox: ${access} access denied for "${path}" (in ${isRead ? "askRead" : "askWrite"})`,
        };
      }
      await applyChoice(choice.action, access, choice.value, ctx.cwd);
      refreshEffectiveAllowances();
      return;
    }

    const allowPaths = isRead ? effective.readPaths : effective.writePaths;
    if (matchesPattern(path, allowPaths, ctx.cwd)) return;

    const choice = await prompt(pi, ctx, path, config.permissionPromptTimeoutSeconds);
    if (choice.action === "abort") {
      return {
        block: true,
        reason: isRead
          ? `Sandbox: read access denied for "${path}"`
          : `Sandbox: write access denied for "${path}" (not in allowWrite)`,
      };
    }
    await applyChoice(choice.action, access, choice.value, ctx.cwd);
    refreshEffectiveAllowances();
  }

  function updateStatus(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
    config: ReturnType<typeof loadConfig>,
  ) {
    ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", formatSandboxStatus(config)));
  }

  async function enableSandbox(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
    setProxyEnvironment: boolean,
  ): Promise<boolean> {
    if (sandboxEnabled) {
      toolPolicyState = "active";
      ctx.ui.notify("Sandbox is already enabled", "info");
      return false;
    }
    toolPolicyState = "unavailable";

    const config = loadConfig(ctx.cwd);
    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
      return false;
    }

    try {
      await initializeSandbox(config, allowances);
      if (setProxyEnvironment && supportsNodeEnvProxy(process.versions.node)) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }
      sandboxEnabled = true;
      sandboxInitialized = true;
      toolPolicyState = "active";
      if (platform === "linux") {
        const unsupportedPatterns = unsupportedLinuxDenyWritePatterns(
          config.filesystem?.denyWrite ?? [],
        );
        if (unsupportedPatterns.length > 0) {
          ctx.ui.notify(
            `Sandbox: Linux OS-level denyWrite does not support these glob patterns: ${unsupportedPatterns.map((pattern) => JSON.stringify(pattern)).join(", ")}. ` +
              "They are not enforced for bash; use literal paths for OS-level enforcement.",
            "warning",
          );
        }
      }
      warnIfAllDomainsAllowed(ctx, config);
      updateStatus(ctx, config);
      return true;
    } catch (error) {
      sandboxEnabled = false;
      toolPolicyState = "unavailable";
      ctx.ui.notify(
        `Sandbox initialization failed: ${error instanceof Error ? error.message : error}`,
        "error",
      );
      return false;
    }
  }

  async function disableSandbox(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
  ): Promise<boolean> {
    toolPolicyState = "disabled";
    if (!sandboxEnabled) {
      ctx.ui.notify("Sandbox is already disabled", "info");
      return false;
    }

    if (sandboxInitialized) {
      try {
        await SandboxManager.reset();
      } catch {
        // Ignore cleanup errors.
      }
    }
    sandboxEnabled = false;
    sandboxInitialized = false;
    ctx.ui.setStatus("sandbox", "");
    return true;
  }

  async function toggleSandbox(ctx: Parameters<typeof warnIfAllDomainsAllowed>[0]): Promise<void> {
    if (sandboxEnabled) {
      if (await disableSandbox(ctx)) ctx.ui.notify("Sandbox disabled", "info");
      return;
    }
    if (await enableSandbox(ctx, false)) ctx.ui.notify("Sandbox enabled", "info");
  }

  pi.registerTool({
    ...localBash,
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate, ctx) {
      const runBash = () => {
        if (!sandboxEnabled || !sandboxInitialized) {
          return localBash.execute(id, params, signal, onUpdate, ctx);
        }
        return createBashToolDefinition(localCwd, {
          operations: createSandboxedBashOps(
            userShellPath,
            loadConfig(ctx.cwd).network?.sshProxy !== false,
          ),
          shellPath: userShellPath,
        }).execute(id, params, signal, onUpdate, ctx);
      };

      let result: AgentToolResult<any>;
      try {
        result = await runBash();
      } catch (error) {
        if (!(error instanceof Error) || !error.message.includes("Operation not permitted")) {
          throw error;
        }
        result = {
          content: [
            {
              type: "text",
              text: `Error: Command failed with OS-level sandbox restriction: ${error.message}`,
            },
          ],
          details: {},
        };
      }

      if (sandboxEnabled && sandboxInitialized && ctx?.hasUI) {
        const output = result.content
          .filter((content: any) => content.type === "text")
          .map((content: any) => content.text)
          .join("\n");
        const blockedPath = extractBlockedWritePath(output);

        if (blockedPath) {
          const path = canonicalizePath(blockedPath, ctx.cwd);
          const config = loadConfig(ctx.cwd);
          const writePermission = await resolveWritePermission({
            path,
            allowWrite: effectiveAllowances(ctx.cwd).writePaths,
            denyWrite: config.filesystem?.denyWrite ?? [],
            cwd: ctx.cwd,
            prompt: (path) =>
              promptWriteBlock(pi, ctx, path, config.permissionPromptTimeoutSeconds),
            saveWritePermission: (choice, value) => applyChoice(choice, "write", value, ctx.cwd),
          });
          if (writePermission.action === "deny") {
            return result;
          }
          if (writePermission.action === "allow") {
            await refreshSandbox(ctx.cwd);
            return runBash();
          }
          if (writePermission.action === "granted") {
            onUpdate?.({
              content: [
                {
                  type: "text",
                  text: `\n--- Write access granted for "${writePermission.value}", retrying ---\n`,
                },
              ],
              details: {},
            });
            return runBash();
          }
        }
      }
      return result;
    },
  });

  pi.on("user_bash", async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;

    const config = loadConfig(ctx.cwd);
    for (const domain of extractDomainsFromCommand(event.command)) {
      if (!domainIsAllowed(domain, effectiveDomains(ctx.cwd))) {
        const choice = await promptDomainBlock(
          pi,
          ctx,
          domain,
          config.permissionPromptTimeoutSeconds,
        );
        if (choice.action === "abort") {
          return {
            result: {
              output: `Blocked: "${domain}" is not in allowedDomains. Use /sandbox to review your config.`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
        await applyChoice(choice.action, "domain", choice.value, ctx.cwd);
      }
    }
    return {
      operations: createSandboxedBashOps(
        userShellPath,
        loadConfig(ctx.cwd).network?.sshProxy !== false,
      ),
    };
  });

  async function handleToolCall(
    event: ToolCallEvent,
    ctx: ExtensionContext,
  ): Promise<ToolCallEventResult | undefined> {
    const config = loadConfig(ctx.cwd);
    if (!config.enabled || toolPolicyState === "disabled") return;

    const isBash = event.toolName === "bash";
    const toolPolicy = isBash ? undefined : getToolPolicy(config.toolPolicies, event.toolName);
    if (toolPolicyState !== "active") {
      if (toolPolicy) {
        return {
          block: true,
          reason: `Sandbox: blocked "${event.toolName}": filesystem tool enforcement is unavailable because the OS sandbox is not active`,
        };
      }
      return;
    }
    if (!sandboxEnabled) return;

    let effective = resolveAllowances(config, allowances);
    const refreshEffectiveAllowances = () => {
      effective = resolveAllowances(loadConfig(ctx.cwd), allowances);
    };
    const { projectPath, globalPath } = getConfigPaths(ctx.cwd);

    if (sandboxInitialized && isToolCallEventType("bash", event)) {
      for (const domain of extractDomainsFromCommand(event.input.command)) {
        if (!domainIsAllowed(domain, effectiveDomains(ctx.cwd))) {
          const choice = await promptDomainBlock(
            pi,
            ctx,
            domain,
            config.permissionPromptTimeoutSeconds,
          );
          if (choice.action === "abort") {
            return {
              block: true,
              reason: `Network access to "${domain}" is blocked (not in allowedDomains).`,
            };
          }
          await applyChoice(choice.action, "domain", choice.value, ctx.cwd);
        }
      }
    }

    // Bash filesystem access is enforced by the OS-level sandbox, not toolPolicies;
    // a policy for "bash" would misinterpret the command string as a path.
    if (isBash) return;

    if (!toolPolicy) return;
    const extractedPaths = extractToolPaths(event.input, toolPolicy);
    if (!extractedPaths.ok) {
      return {
        block: true,
        reason: `Sandbox: blocked "${event.toolName}": ${extractedPaths.reason}`,
      };
    }

    let paths: string[];
    try {
      paths = [
        ...new Set(
          extractedPaths.paths.map((inputPath) => canonicalizeToolPath(inputPath, ctx.cwd)),
        ),
      ];
    } catch (error) {
      return {
        block: true,
        reason: `Sandbox: could not resolve a path for "${event.toolName}": ${error instanceof Error ? error.message : error}`,
      };
    }

    if (toolPolicy.access === "read") {
      for (const path of paths) {
        const blocked = await authorizeToolPath(
          "read",
          path,
          config,
          effective,
          ctx,
          refreshEffectiveAllowances,
        );
        if (blocked) return blocked;
      }
      return;
    }

    // Check every path against denyWrite before prompting, so a tool call that
    // is doomed to be blocked never asks for an approval it cannot use.
    const denyWrite = config.filesystem?.denyWrite ?? [];
    for (const path of paths) {
      if (!matchesPattern(path, denyWrite, ctx.cwd)) continue;

      return {
        block: true,
        reason:
          `Sandbox: write access denied for "${path}" (in denyWrite). ` +
          `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
      };
    }

    for (const path of paths) {
      const blocked = await authorizeToolPath(
        "write",
        path,
        config,
        effective,
        ctx,
        refreshEffectiveAllowances,
      );
      if (blocked) return blocked;
    }
  }

  // Fail closed: any unexpected enforcement error (e.g. a throwing prompt UI)
  // blocks the tool call instead of letting it proceed unchecked.
  pi.on("tool_call", async (event, ctx) => {
    try {
      return await handleToolCall(event, ctx);
    } catch (error) {
      return {
        block: true,
        reason:
          `Sandbox: enforcement error, blocking "${event.toolName}" (fail-closed): ` +
          `${error instanceof Error ? error.message : error}`,
      };
    }
  });

  pi.on("session_start", async (_event, ctx) => {
    if (pi.getFlag("no-sandbox") as boolean) {
      sandboxEnabled = false;
      toolPolicyState = "disabled";
      ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
      return;
    }
    if (!loadConfig(ctx.cwd).enabled) {
      sandboxEnabled = false;
      toolPolicyState = "disabled";
      ctx.ui.notify("Sandbox disabled via config", "info");
      return;
    }
    await enableSandbox(ctx, true);
  });

  pi.on("session_shutdown", async () => {
    if (!sandboxInitialized) return;
    try {
      await SandboxManager.reset();
    } catch {
      // Ignore cleanup errors.
    }
  });

  pi.registerShortcut(Key.alt("s"), {
    description: "Toggle sandbox on/off for this session",
    handler: toggleSandbox,
  });

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (await enableSandbox(ctx, false)) ctx.ui.notify("Sandbox enabled", "info");
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (await disableSandbox(ctx)) ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox-allow", {
    description: "Prompt to allow a domain or read/write access to a file path",
    handler: async (args, ctx) => {
      const [kind, ...targetParts] = args.trim().split(/\s+/);
      const targetArg = targetParts.join(" ");

      if ((kind !== "domain" && kind !== "read" && kind !== "write") || !targetArg) {
        ctx.ui.notify("Usage: /sandbox-allow <domain|read|write> <domain-or-path>", "error");
        return;
      }

      const target = kind === "domain" ? targetArg : canonicalizePath(targetArg, ctx.cwd);
      const config = loadConfig(ctx.cwd);
      const configKey =
        kind === "domain" ? "allowedDomains" : kind === "read" ? "allowRead" : "allowWrite";
      const choice = await showPermissionPrompt(
        pi,
        ctx,
        `Add ${target} to ${configKey}?`,
        target,
        (value) => {
          if (!value) return "Rule cannot be empty.";
          const matches =
            kind === "domain"
              ? domainIsAllowed(target, [value])
              : matchesPattern(target, [value], ctx.cwd);
          return matches ? null : `Rule must match "${target}".`;
        },
        config.permissionPromptTimeoutSeconds,
      );
      if (choice.action === "abort") {
        ctx.ui.notify("Allow cancelled", "info");
        return;
      }

      await applyChoice(choice.action, kind, choice.value, ctx.cwd);
      ctx.ui.notify(`Added ${choice.value} to ${configKey}`, "info");
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is disabled", "info");
        return;
      }
      ctx.ui.notify(
        formatSandboxConfiguration(loadConfig(ctx.cwd), getConfigPaths(ctx.cwd), allowances),
        "info",
      );
    },
  });
}
