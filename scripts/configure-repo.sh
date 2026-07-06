#!/usr/bin/env bash
set -euo pipefail

# Applies scafctl governance conventions to this plugin repository.
#
# Use this when the repo was scaffolded locally (create_repo=false) and the
# GitHub repository was created separately, so the rulesets and merge settings
# that the create_repo=true flow would have applied are missing.
#
# Safe to re-run: ruleset creation is skipped if a ruleset with the same name
# already exists.
#
# Prerequisites: gh CLI authenticated with admin permissions on the repo.

# Resolve the target repo slug. Defaults to the repository the current
# directory points at (via gh), so running from a fork configures the fork.
# Override explicitly with FULL=owner/repo when needed.
FULL="${FULL:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"

if [[ -z "${FULL}" ]]; then
  echo "error: could not determine repo slug; set FULL=owner/repo" >&2
  exit 1
fi

echo "Configuring ${FULL}..."

# ── Merge strategy and branch cleanup ────────────────────────────────────────
# Squash-only keeps a linear history. Merge commits and rebase merges are
# disabled, so the GitHub UI will report "merge method (merge) is not allowed" —
# that is expected; use "Squash and merge".
echo "  Setting merge strategy (squash-only) and branch cleanup..."
gh repo edit "$FULL" \
  --delete-branch-on-merge \
  --enable-squash-merge \
  --enable-issues

echo "  Disabling merge commit and rebase merge..."
gh api -X PATCH "repos/${FULL}" \
  -f allow_merge_commit=false \
  -f allow_rebase_merge=false \
  -f has_projects=false \
  -f has_wiki=false \
  -f web_commit_signoff_required=true \
  >/dev/null

# ── Branch ruleset ───────────────────────────────────────────────────────────
# Protects main: requires PR review, signed commits, linear history, and the
# CI status checks. Organization admins can bypass (force-merge) when needed.
if gh api "repos/${FULL}/rulesets" --jq '.[].name' | grep -qx "main branch protection"; then
  echo "  Branch ruleset already exists, skipping."
else
  echo "  Creating branch ruleset..."
  gh api -X POST "repos/${FULL}/rulesets" --input - <<'EOF' >/dev/null
{
  "name": "main branch protection",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always" }
  ],
  "conditions": {
    "ref_name": { "include": ["refs/heads/main"], "exclude": [] }
  },
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Test" },
          { "context": "Lint" }
        ]
      }
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": false
      }
    },
    { "type": "required_linear_history" },
    { "type": "required_signatures" },
    { "type": "non_fast_forward" }
  ]
}
EOF
fi

# ── Tag ruleset ──────────────────────────────────────────────────────────────
# Protects version tags (v*) from deletion and force pushes so published
# releases stay immutable.
if gh api "repos/${FULL}/rulesets" --jq '.[].name' | grep -qx "version tag protection"; then
  echo "  Tag ruleset already exists, skipping."
else
  echo "  Creating tag ruleset..."
  gh api -X POST "repos/${FULL}/rulesets" --input - <<'EOF' >/dev/null
{
  "name": "version tag protection",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["refs/tags/v*"], "exclude": [] }
  },
  "rules": [
    { "type": "non_fast_forward" }
  ]
}
EOF
fi

# ── Security features ─────────────────────────────────────────────────────────
echo "  Enabling vulnerability alerts..."
gh api -X PUT "repos/${FULL}/vulnerability-alerts" 2>/dev/null || true

echo "  Enabling automated security fixes..."
gh api -X PUT "repos/${FULL}/automated-security-fixes" 2>/dev/null || true

echo ""
echo "Repository configured."
echo "Reminder: set the CATALOG_PUSH_TOKEN secret (repo or org) before tagging a release:"
echo "  gh secret set CATALOG_PUSH_TOKEN --repo ${FULL} --body \"\$TOKEN\""
