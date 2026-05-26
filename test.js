const test = require("node:test");
const assert = require("node:assert/strict");

const { normalizePolicy, validatePolicyStructure, renderSummary } = require("./index");

test("validates legacy MeshGuard policy shape", () => {
  const issues = validatePolicyStructure(
    {
      name: "legacy",
      version: "1.0.0",
      appliesTo: { trustTiers: ["verified"] },
      rules: [{ effect: "allow", actions: ["read:*"] }],
      defaultEffect: "deny",
    },
    "policy.yaml",
  );

  assert.equal(issues.filter((i) => i.level === "error").length, 0);
});

test("validates AGT governance.toolkit/v1 policy shape", () => {
  const policy = {
    apiVersion: "governance.toolkit/v1",
    kind: "Policy",
    metadata: { name: "agt-policy", version: "1.2.3" },
    spec: {
      defaultEffect: "deny",
      rules: [{ effect: "allow", actions: ["read:ticket"] }],
    },
  };

  assert.equal(normalizePolicy(policy).name, "agt-policy");
  const issues = validatePolicyStructure(policy, "agt.yaml");
  assert.equal(issues.filter((i) => i.level === "error").length, 0);
});

test("renders GitHub step summary markdown", () => {
  const summary = renderSummary({
    mode: "validate",
    filesScanned: 1,
    files: [{ file: "policy.yaml", name: "prod", valid: true, rules: 2 }],
    issues: [],
    result: "pass",
  });

  assert.match(summary, /MeshGuard Policy Check/);
  assert.match(summary, /policy.yaml/);
});
