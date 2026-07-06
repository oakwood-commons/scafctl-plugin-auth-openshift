# Getting Started

This guide walks the full lifecycle of scafctl-plugin-auth-openshift: from a fresh scaffold to a
published catalog release. Run the steps in order the first time.

## Prerequisites

- Go (matching the version in [go.mod](go.mod))
- [Task](https://taskfile.dev) (`task`)
- [golangci-lint](https://golangci-lint.run)
- [GitHub CLI](https://cli.github.com) (`gh`), authenticated with admin rights on the repo
- Commit signing configured (GPG or SSH). All commits must be signed and DCO signed-off.

## 1. Resolve dependencies and make the first push

The initial scaffold does not include `go.sum` -- CI fails until you generate and
push it.

```bash
go mod tidy
git add go.mod go.sum
git commit -s -S -m "chore: add go.sum"
git push
```

`-s` adds the DCO sign-off; `-S` signs the commit. Both are required by the
branch ruleset.

## 2. Apply repository governance

If this repository was created with the template's `create_repo=true` flow, the
rulesets and merge settings are already in place -- skip to step 3.

If you scaffolded locally and created the GitHub repo separately, apply the same
governance now:

```bash
task repo:configure
```

This sets squash-only merges, branch and tag rulesets (signed commits, linear
history, required CI checks), and security features. Organization admins keep a
bypass so they can force-merge when necessary.

## 3. Day-to-day development

```bash
task ci            # lint + test + build, the same checks CI runs
```

Open changes as pull requests against `main`:

- The repo is **squash-only**. The GitHub UI shows "the selected merge method
  (merge) is not allowed" if you pick *Create a merge commit* -- that is by
  design. Choose **Squash and merge**.
- PRs require one approval, passing `lint` and `test` checks, and signed commits.

## 4. Verify end-to-end locally

```bash
task release:local VERSION=0.1.0
scafctl auth login openshift
```

Confirm the host registers the **openshift** auth handler and that
login establishes authenticated state.

## 5. Publish a release

Releases are tag-driven. Pushing a `v*` tag triggers the release workflow, which
builds binaries, publishes the catalog artifact, **and refreshes the catalog
index** so the plugin is discoverable.

Before the first release, make sure the publishing secret exists (repo or org
level):

```bash
gh secret set CATALOG_PUSH_TOKEN --repo oakwood-commons/scafctl-plugin-auth-openshift --body "$TOKEN"
```

`CATALOG_PUSH_TOKEN` needs `repo`, `read:packages`, and `write:packages` scopes.
For official plugins, use a machine account or GitHub App rather than a personal
token.

Then, once your changes are merged to `main`:

```bash
git checkout main && git pull
task release:tag VERSION=0.1.0
```

This creates a signed `v0.1.0` tag and pushes it. Watch the **Release** workflow
in the Actions tab; when it completes, the plugin is published and the catalog
index is updated.

## Reference

- Release details and required secrets: see the **Release** section of [README.md](README.md).
- Provider/auth-handler semantics and conventions: see [.github/copilot-instructions.md](.github/copilot-instructions.md).
