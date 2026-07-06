---
description: "Fetch and triage PR review comments and CI failures for the current branch. Presents findings for approval before handing off to fixes."
agent: "pr-reviewer"
argument-hint: "Optional: PR number or leave blank to use current branch"
---
Triage unresolved PR review comments and CI failures. Use `gh` CLI and the **GitHub GraphQL API (v4)** to fetch review threads -- the REST API does not expose the `isResolved` field.

Follow these phases **in order** -- do not skip ahead:

1. **Fetch**: Fetch all review threads via GraphQL; **skip comments that are already resolved**. Include **outdated but unresolved** threads -- these still need a response and resolution even if the code has moved
2. **Pipeline check**: Run `gh pr checks <PR_NUMBER>` to see CI status. If any checks are failing, run `gh run view <RUN_ID> --log-failed` to get failure logs. Include pipeline failures in the triage summary alongside review comments -- they may overlap with reviewer feedback or reveal additional issues
3. **Coverage check**: Assess patch coverage against the **70% target** (see `codecov.yml`):
   - Resolve the repo slug: `gh repo view --json owner,name --jq '.owner.login + "/" + .name'`
   - Look for a Codecov report on the PR: `gh pr view <PR_NUMBER> --json comments --jq '.comments[] | select(.body | contains("Codecov")) | .body'`
   - If Codecov has not reported yet (common on a fresh repo), fall back to local coverage: run `task test:cover` (writes a coverprofile to `cover/cover.out`), then `go tool cover -func=cover/cover.out` for per-file coverage (`-html` for line-level detail)
   - Present a **sorted table** of files with missed lines > 0: file path, missed lines, patch %
   - Flag any files with **0% patch coverage** -- these are the highest priority
   - Note the overall **patch coverage %** and whether it meets the **70% target**; if below, list the files where adding tests has the most impact (most missed lines)
4. **Early exit**: If there are **zero unresolved threads**, **all checks are passing**, and **patch coverage >= 70%**, report that and stop
5. **Triage**: For each unresolved comment, pipeline failure, and coverage gap, assess whether it's a legit problem with the code. Present the triage summary with recommendations and **stop here** -- wait for the user's approval before applying any fixes

Include thread IDs in the triage output so fixes can be linked to resolved threads afterward.

## After approval

Once the user approves, **do not edit code yourself**. Delegate every approved fix to the `go-fixer` agent (the "Apply fixes" handoff / `runSubagent`), passing each item's file, the reviewer's concern, and its **thread ID**. After go-fixer reports the changes verified (`go build`, `go vet`, `task lint`, `task test`, and patch coverage >= **70%**), reply to and resolve each thread via the GraphQL mutations.

- **Never edit `.go` files directly from this prompt** -- all code changes go through `go-fixer`.
- If the `go-fixer` agent cannot be invoked, **report the actual tool error and stop** -- do not fall back to editing code yourself.
- **NEVER** run `git commit` or `git push`.
