# scafctl-plugin-auth-openshift

OpenShift auth handler for scafctl - one login via web OAuth or Entra with the credential held by scafctl

> New here? See [GETTING_STARTED.md](GETTING_STARTED.md) for the full setup,
> governance, and first-release walkthrough.

## Names

This plugin uses the following names across different surfaces:

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-auth-openshift` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-auth-openshift` |
| Binary | `scafctl-plugin-auth-openshift` |
| Handler name | `openshift` |
| Catalog artifact | `openshift` |

The **handler name** is what users reference in solutions (`authProvider: openshift`).
It comes from the RPC contract (`GetAuthHandlers`), not from the binary filename.

## Documentation

- [Design: OpenShift auth handler](docs/design/openshift-auth.md) -- architecture,
  auto-detection fork, web-login flow, and credential custody (with diagrams).
- [Tutorial: Log into OpenShift once](docs/tutorials/openshift-login.md) -- end-to-end
  walkthrough (login -> kubectl -> solutions -> SA tokens -> registry -> logout).

## Installation

```bash
# Build from source
task build

# Or download from releases
gh release download --repo github.com/oakwood-commons/scafctl-plugin-auth-openshift
```

## Usage

### Log into a cluster (kubectl / oc)

`kube login` authenticates and writes a kubeconfig exec-credential entry, so
`kubectl`/`oc` mint fresh tokens on demand:

```bash
scafctl kube login <cluster> --handler openshift --server https://api.<cluster>:6443
oc whoami
```

### Resolve clusters by name (fleet inventory)

Configure `kube.clusters` so a cluster resolves by name -- no `--server` or
`--handler` needed. A static alias for one-off clusters:

```yaml
kube:
  clusters:
    aliases:
      lab:
        server: https://api.lab.example.com:6443
        defaultHandler: openshift
        authType: oauth
```

Or a dynamic fleet inventory (HTTP fetch + CEL transform), stamping the handler
and auth type on every entry so `kube login <cluster>` needs no flags:

```yaml
kube:
  clusters:
    resolver:
      source:
        url: https://clusters.example.com/
      transform: '_.map(k, {"name": k, "url": _[k].apiServerURL, "defaultHandler": "openshift", "authType": "oauth"})'
      ttl: 10m
```

Then:

```bash
scafctl kube login prod        # resolves server + handler from config
oc get pods
```

### Multiple clusters at once

Log into several clusters; each kubeconfig context mints its own per-cluster
token (the handler advertises `token_hostname`), so they work simultaneously
without clobbering one another:

```bash
scafctl kube login prod
scafctl kube login staging
oc --context prod whoami
oc --context staging whoami
```

### Service-account tokens

Mint a scoped service-account token via the Kubernetes TokenRequest API (your
logged-in user needs RBAC to create `serviceaccounts/token` in the namespace):

```bash
scafctl auth token openshift --scope "<namespace>/<serviceaccount>"
# optional audience: --scope "<namespace>/<serviceaccount>@<audience>"
```

The OAuth login uses a loopback callback; on locked-down networks you can pin
the port with `scafctl auth login openshift --hostname <cluster> --callback-port <port>`.

### Log out

```bash
scafctl kube logout <cluster>   # remove one cluster's kubeconfig entry + cached token
scafctl auth logout openshift   # clear all cached openshift credentials
```

### Use in a solution

Reference the handler by name in HTTP requests:

```yaml
resolvers:
  data:
    resolve:
      with:
        - provider: http
          inputs:
            url: https://api.example.com/data
            authProvider: openshift
```

> The user OAuth credential comes from the browser implicit-grant flow, which
> has no refresh token. When it expires (~24h), re-run
> `scafctl kube login <cluster>`.

## Development

```bash
# Run tests
task test

# Run linter
task lint

# Build
task build

# Full CI pipeline (lint + test + build)
task ci
```



## Release

### Publishing to a catalog

A tagged release should publish both the plugin artifact and refresh the
catalog index:

```bash
# Publish the plugin artifact
scafctl catalog push openshift --version v1.0.0

# Refresh the catalog index so the plugin is discoverable
scafctl catalog index push --catalog oci://ghcr.io/<REGISTRY_OWNER>
```

Both steps are required. Publishing the artifact alone does not make the
plugin appear in catalog listings.

### CI release workflow

scafctl reads container registry credentials from `~/.docker/config.json`. The
release workflow writes that file directly using the publishing token:

```bash
mkdir -p ~/.docker
AUTH="$(printf '%s' "${GITHUB_ACTOR}:${CATALOG_PUSH_TOKEN}" | base64 -w0)"
printf '{"auths":{"ghcr.io":{"auth":"%s"}}}' "${AUTH}" > ~/.docker/config.json
```

> **Avoid** `scafctl auth login github --flow pat --write-registry-auth`. As of
> scafctl 0.27.0 that PAT-flow registry bridge fails with
> `tokenprovider: source not found: github` even though login reports success.
> Writing `~/.docker/config.json` directly (as above) is the reliable path.

### Required secrets

| Secret | Scopes | Purpose |
|--------|--------|---------|
| `GITHUB_TOKEN` | Default | Build, test, create release |
| `CATALOG_PUSH_TOKEN` | `repo`, `read:packages`, `write:packages` | Publish artifact and refresh catalog index |

Create the publishing secret at the org or repo level:

```bash
gh secret set CATALOG_PUSH_TOKEN --org <ORG> --repos scafctl-plugin-auth-openshift --body "$TOKEN"
```

### Token strategy

For official providers, use a machine account or GitHub App for the publishing
token rather than a personal account. This avoids tying release capability to
an individual developer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.