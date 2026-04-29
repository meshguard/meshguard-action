# MeshGuard Policy Check — GitHub Action

Validate MeshGuard policies and run governance dry-run checks in CI pipelines.

## Overview

This action scans YAML policy files in your repository and either validates their structure locally or tests them against a live MeshGuard gateway. Use it in pull requests to catch policy misconfigurations before they reach production.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `gateway-url` | Yes | — | MeshGuard gateway URL |
| `api-key` | Yes | — | MeshGuard API key |
| `policy-path` | No | `policies/` | Path to YAML policy files |
| `check-mode` | No | `validate` | `validate` (syntax only) or `dry-run` (test against gateway) |
| `fail-on-warning` | No | `false` | Fail the action if any warnings are found |
| `agent-id` | No | — | Agent ID for dry-run checks |
| `actions` | No | — | Comma-separated actions to test in dry-run mode |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | `pass` or `fail` |
| `details` | JSON string with validation results |

## Usage

### Validate mode (syntax check)

Parses each YAML policy file and checks that the structure is valid: `name` is present, `rules` is a non-empty array, each rule has a valid `effect` and `actions`, etc.

```yaml
name: Validate Policies
on:
  pull_request:
    paths:
      - "policies/**"

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: MeshGuard policy check
        uses: meshguard/meshguard-action@v1
        with:
          gateway-url: ${{ secrets.MESHGUARD_GATEWAY_URL }}
          api-key: ${{ secrets.MESHGUARD_API_KEY }}
          policy-path: policies/
          check-mode: validate
```

### Dry-run mode (gateway validation + action tests)

Sends each policy to the gateway's `/admin/policies/validate` endpoint, then tests specific actions against `/admin/policies/test`.

```yaml
name: Dry-Run Policy Tests
on:
  pull_request:
    paths:
      - "policies/**"

jobs:
  dry-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: MeshGuard dry-run check
        id: policy-check
        uses: meshguard/meshguard-action@v1
        with:
          gateway-url: ${{ secrets.MESHGUARD_GATEWAY_URL }}
          api-key: ${{ secrets.MESHGUARD_API_KEY }}
          policy-path: policies/
          check-mode: dry-run
          agent-id: agent-ci-test
          actions: "read:data,write:config,tool:exec"
          fail-on-warning: "true"

      - name: Show results
        if: always()
        run: |
          echo "Result: ${{ steps.policy-check.outputs.result }}"
          echo '${{ steps.policy-check.outputs.details }}' | jq .
```

### Using outputs in downstream steps

```yaml
      - name: Gate deployment
        if: steps.policy-check.outputs.result == 'fail'
        run: |
          echo "Policy check failed — blocking deploy"
          exit 1
```

## Policy file format

Policy YAML files should follow the MeshGuard policy schema:

```yaml
name: production-guardrails
version: "1.0"
description: Restrict dangerous actions for unverified agents

appliesTo:
  trustTiers:
    - unverified
    - basic

rules:
  - effect: deny
    actions:
      - "tool:exec"
      - "admin:*"
      - "write:delete"
  - effect: allow
    actions:
      - "read:*"

defaultEffect: deny
```

### Required fields

- `name` — Policy name (string)
- `rules` — Non-empty array of rule objects
  - `rules[].effect` — `allow` or `deny`
  - `rules[].actions` — Non-empty array of action patterns

### Validated but optional

- `version` — Triggers a warning if missing
- `appliesTo` — Object with `trustTiers`, `agentIds`, `tags`, or `orgIds`
- `defaultEffect` — `allow` or `deny` (defaults to `deny`)

## Local development

```bash
npm install
# Set required env vars for @actions/core
export INPUT_GATEWAY-URL="http://localhost:4000"
export INPUT_API-KEY="test-key"
export INPUT_POLICY-PATH="./test-policies"
export INPUT_CHECK-MODE="validate"
node index.js
```
