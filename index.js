const core = require("@actions/core");
const glob = require("@actions/glob");
const yaml = require("js-yaml");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Policy structure validation (validate mode)
// ---------------------------------------------------------------------------

/**
 * Validate a single parsed policy object for correct structure.
 * Returns an array of { level: "error"|"warning", message } objects.
 */
function validatePolicyStructure(policy, filePath) {
  const issues = [];

  if (!policy || typeof policy !== "object") {
    issues.push({ level: "error", message: `${filePath}: file does not contain a valid YAML object` });
    return issues;
  }

  const normalized = normalizePolicy(policy);

  if (normalized.apiVersion && normalized.apiVersion !== "governance.toolkit/v1") {
    issues.push({
      level: "warning",
      message: `${filePath}: unsupported apiVersion "${normalized.apiVersion}"; expected governance.toolkit/v1 for AGT-compatible policies`,
    });
  }

  if (!normalized.name) {
    issues.push({ level: "error", message: `${filePath}: missing required policy name` });
  }

  if (!normalized.version) {
    issues.push({ level: "warning", message: `${filePath}: missing field "version"` });
  }

  if (!normalized.appliesTo || typeof normalized.appliesTo !== "object") {
    issues.push({ level: "warning", message: `${filePath}: missing "appliesTo"; policy may need tenant-side bindings` });
  } else {
    const hasScope =
      (Array.isArray(normalized.appliesTo.trustTiers) && normalized.appliesTo.trustTiers.length > 0) ||
      (Array.isArray(normalized.appliesTo.agentIds) && normalized.appliesTo.agentIds.length > 0) ||
      (Array.isArray(normalized.appliesTo.tags) && normalized.appliesTo.tags.length > 0) ||
      (Array.isArray(normalized.appliesTo.orgIds) && normalized.appliesTo.orgIds.length > 0);
    if (!hasScope) {
      issues.push({
        level: "warning",
        message: `${filePath}: "appliesTo" has no trustTiers, agentIds, tags, or orgIds — policy will not match any agents`,
      });
    }
  }

  // Rules array
  if (!Array.isArray(normalized.rules) || normalized.rules.length === 0) {
    issues.push({ level: "error", message: `${filePath}: missing or empty "rules" array` });
  } else {
    normalized.rules.forEach((rule, i) => {
      const effect = String(rule.effect || "").toLowerCase();
      if (!effect || !["allow", "deny", "require_approval"].includes(effect)) {
        issues.push({
          level: "error",
          message: `${filePath}: rule[${i}] has invalid or missing "effect" (must be allow, deny, or require_approval)`,
        });
      }
      if (!Array.isArray(rule.actions) || rule.actions.length === 0) {
        issues.push({
          level: "error",
          message: `${filePath}: rule[${i}] has invalid or missing "actions" array`,
        });
      }
    });
  }

  // defaultEffect
  const defaultEffect = String(normalized.defaultEffect || "").toLowerCase();
  if (!defaultEffect || !["allow", "deny"].includes(defaultEffect)) {
    issues.push({
      level: "warning",
      message: `${filePath}: missing or invalid "defaultEffect" (should be "allow" or "deny"); defaults to "deny"`,
    });
  }

  return issues;
}

function normalizePolicy(policy) {
  const spec = policy.spec && typeof policy.spec === "object" ? policy.spec : policy;
  return {
    apiVersion: policy.apiVersion,
    kind: policy.kind,
    name: policy.name || policy.metadata?.name,
    version: policy.version || policy.metadata?.version || spec.version,
    appliesTo: policy.appliesTo || spec.appliesTo || spec.bindings,
    rules: policy.rules || spec.rules,
    defaultEffect: policy.defaultEffect || spec.defaultEffect,
  };
}

// ---------------------------------------------------------------------------
// Gateway helpers (dry-run mode)
// ---------------------------------------------------------------------------

async function postJSON(url, body, apiKey) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  return { status: res.status, ok: res.ok, data };
}

/**
 * Validate a policy against the gateway's /admin/policies/validate endpoint.
 */
async function gatewayValidate(gatewayUrl, apiKey, policy, filePath) {
  const url = `${gatewayUrl.replace(/\/+$/, "")}/admin/policies/validate`;
  try {
    const res = await postJSON(url, policy, apiKey);
    if (res.ok) {
      return { file: filePath, valid: true, response: res.data };
    }
    return { file: filePath, valid: false, response: res.data, status: res.status };
  } catch (err) {
    return { file: filePath, valid: false, error: err.message };
  }
}

/**
 * Test a policy + action against the gateway's /admin/policies/test endpoint.
 */
async function gatewayTest(gatewayUrl, apiKey, policy, agentId, action) {
  const url = `${gatewayUrl.replace(/\/+$/, "")}/admin/policies/test`;
  const body = {
    policy,
    agentId,
    action,
  };
  try {
    const res = await postJSON(url, body, apiKey);
    return { action, ok: res.ok, status: res.status, data: res.data };
  } catch (err) {
    return { action, ok: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

async function findPolicyFiles(policyPath) {
  const patterns = [
    path.join(policyPath, "**/*.yaml"),
    path.join(policyPath, "**/*.yml"),
  ];
  const globber = await glob.create(patterns.join("\n"));
  const files = await globber.glob();
  return files.sort();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run() {
  const gatewayUrl = core.getInput("gateway-url");
  const apiKey = core.getInput("api-key");
  const policyPath = core.getInput("policy-path") || "policies/";
  const checkMode = core.getInput("check-mode") || "validate";
  const failOnWarning = core.getInput("fail-on-warning") === "true";
  const agentId = core.getInput("agent-id") || "";
  const actionsRaw = core.getInput("actions") || "";
  const historicalWindow = core.getInput("historical-window") || "";

  const actionsList = actionsRaw
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean);

  // Discover policy files
  const resolvedPath = path.resolve(policyPath);
  core.info(`Scanning for policy files in: ${resolvedPath}`);

  const files = await findPolicyFiles(resolvedPath);

  if (files.length === 0) {
    core.warning(`No .yaml/.yml files found in ${resolvedPath}`);
    core.setOutput("result", "pass");
    core.setOutput("details", JSON.stringify({ files: [], issues: [] }));
    return;
  }

  core.info(`Found ${files.length} policy file(s)`);

  // Collect results
  const allIssues = [];
  const fileResults = [];
  let hasError = false;
  let hasWarning = false;

  // -- VALIDATE MODE -------------------------------------------------------
  if (checkMode === "validate") {
    for (const filePath of files) {
      const relPath = path.relative(process.cwd(), filePath);
      core.info(`Validating: ${relPath}`);

      let content;
      try {
        content = fs.readFileSync(filePath, "utf8");
      } catch (err) {
        const issue = { level: "error", message: `${relPath}: cannot read file — ${err.message}` };
        allIssues.push(issue);
        core.error(issue.message);
        hasError = true;
        continue;
      }

      let parsed;
      try {
        parsed = yaml.load(content);
      } catch (err) {
        const issue = { level: "error", message: `${relPath}: invalid YAML — ${err.message}` };
        allIssues.push(issue);
        core.error(issue.message);
        hasError = true;
        continue;
      }

      const issues = validatePolicyStructure(parsed, relPath);
      const normalized = normalizePolicy(parsed);
      allIssues.push(...issues);

      for (const issue of issues) {
        if (issue.level === "error") {
          core.error(issue.message);
          hasError = true;
        } else {
          core.warning(issue.message);
          hasWarning = true;
        }
      }

      if (!issues.some((i) => i.level === "error")) {
        core.info(`  OK: ${normalized.name} — ${normalized.rules?.length ?? 0} rule(s)`);
        fileResults.push({ file: relPath, name: normalized.name, valid: true, rules: normalized.rules?.length ?? 0 });
      } else {
        fileResults.push({ file: relPath, valid: false });
      }
    }
  }

  // -- DRY-RUN MODE --------------------------------------------------------
  else if (checkMode === "dry-run") {
    if (!gatewayUrl || !apiKey) {
      core.setFailed("gateway-url and api-key are required when check-mode=dry-run");
      return;
    }

    for (const filePath of files) {
      const relPath = path.relative(process.cwd(), filePath);
      core.info(`Dry-run validating: ${relPath}`);

      let content;
      try {
        content = fs.readFileSync(filePath, "utf8");
      } catch (err) {
        const issue = { level: "error", message: `${relPath}: cannot read file — ${err.message}` };
        allIssues.push(issue);
        core.error(issue.message);
        hasError = true;
        continue;
      }

      let parsed;
      try {
        parsed = yaml.load(content);
      } catch (err) {
        const issue = { level: "error", message: `${relPath}: invalid YAML — ${err.message}` };
        allIssues.push(issue);
        core.error(issue.message);
        hasError = true;
        continue;
      }
      const normalized = normalizePolicy(parsed);

      // 1. Validate against gateway
      const valResult = await gatewayValidate(gatewayUrl, apiKey, parsed, relPath);
      if (!valResult.valid) {
        const msg = valResult.error
          ? `${relPath}: gateway validation error — ${valResult.error}`
          : `${relPath}: gateway rejected policy (HTTP ${valResult.status}) — ${JSON.stringify(valResult.response)}`;
        allIssues.push({ level: "error", message: msg });
        core.error(msg);
        hasError = true;
        fileResults.push({ file: relPath, valid: false, gatewayResponse: valResult.response });
        continue;
      }

      core.info(`  Gateway validated: ${normalized.name}`);

      // 2. Test each action if agent-id and actions provided
      const testResults = [];
      if (agentId && actionsList.length > 0) {
        for (const action of actionsList) {
          core.info(`  Testing action: ${action} (agent: ${agentId})`);
          const testResult = await gatewayTest(gatewayUrl, apiKey, parsed, agentId, action);
          testResults.push(testResult);

          if (!testResult.ok) {
            const msg = testResult.error
              ? `${relPath}: dry-run test failed for "${action}" — ${testResult.error}`
              : `${relPath}: dry-run test failed for "${action}" (HTTP ${testResult.status}) — ${JSON.stringify(testResult.data)}`;
            allIssues.push({ level: "error", message: msg });
            core.error(msg);
            hasError = true;
          } else {
            const decision = testResult.data?.decision || "unknown";
            core.info(`    Result: ${decision}`);
          }
        }
      }

      fileResults.push({
        file: relPath,
        name: normalizePolicy(parsed).name,
        valid: true,
        gatewayValidated: true,
        tests: testResults,
        historicalWindow: historicalWindow || undefined,
      });
    }
  } else {
    core.setFailed(`Unknown check-mode: "${checkMode}". Must be "validate" or "dry-run".`);
    return;
  }

  // -- Results summary ------------------------------------------------------
  const overallResult = hasError || (failOnWarning && hasWarning) ? "fail" : "pass";

  const details = JSON.stringify({
    mode: checkMode,
    filesScanned: files.length,
    files: fileResults,
    issues: allIssues,
  });
  const markdownSummary = renderSummary({
    mode: checkMode,
    filesScanned: files.length,
    files: fileResults,
    issues: allIssues,
    result: overallResult,
  });

  core.setOutput("result", overallResult);
  core.setOutput("details", details);
  core.setOutput("summary", markdownSummary);
  writeStepSummary(markdownSummary);

  core.info("");
  core.info("=== MeshGuard Policy Check Summary ===");
  core.info(`Mode:    ${checkMode}`);
  core.info(`Files:   ${files.length}`);
  core.info(`Errors:  ${allIssues.filter((i) => i.level === "error").length}`);
  core.info(`Warnings:${allIssues.filter((i) => i.level === "warning").length}`);
  core.info(`Result:  ${overallResult.toUpperCase()}`);

  if (overallResult === "fail") {
    core.setFailed("MeshGuard policy check failed. See annotations above for details.");
  }
}

function renderSummary(details) {
  const errors = details.issues.filter((i) => i.level === "error").length;
  const warnings = details.issues.filter((i) => i.level === "warning").length;
  const lines = [
    "## MeshGuard Policy Check",
    "",
    `Result: **${details.result.toUpperCase()}**`,
    `Mode: \`${details.mode}\``,
    `Files: ${details.filesScanned}`,
    `Errors: ${errors}`,
    `Warnings: ${warnings}`,
    "",
    "| File | Policy | Status | Rules |",
    "|---|---|---|---|",
  ];

  for (const file of details.files) {
    lines.push(
      `| \`${file.file}\` | ${file.name || ""} | ${file.valid ? "pass" : "fail"} | ${file.rules ?? ""} |`,
    );
  }

  if (details.issues.length) {
    lines.push("", "### Issues");
    for (const issue of details.issues) {
      lines.push(`- **${issue.level}**: ${issue.message}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

function writeStepSummary(markdownSummary) {
  if (!process.env.GITHUB_STEP_SUMMARY) return;
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdownSummary);
}

if (require.main === module) {
  run().catch((err) => {
    core.setFailed(`Unexpected error: ${err.message}`);
  });
}

module.exports = {
  normalizePolicy,
  validatePolicyStructure,
  renderSummary,
};
