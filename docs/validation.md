# OpenShift auth handler - manual validation

A copy-paste checklist to validate the `openshift` scafctl auth handler end to
end against a real cluster.

Set these variables to your own values first; the commands below use them so no
cluster-specific details are hardcoded:

```bash
export CLUSTER1=<your-cluster-alias>          # a cluster in your kube.clusters resolver/aliases
export CLUSTER2=<your-second-cluster-alias>   # a second cluster, for multi-cluster checks
export SERVER1=https://api.example.com:6443   # CLUSTER1's API server URL (or just use $CLUSTER1)
export USER_EMAIL=you@example.com             # the identity you expect to log in as
export NS_SA=<namespace>/<serviceaccount>     # namespace/SA for token tests, e.g. my-ns/default
```

Prereqs: you are on the network/VPN that resolves the cluster hostname, and the
`openshift` handler is installed (or resolvable by name from the catalog).

## 0. Environment

```bash
scafctl version                      # confirm the build/commit under test
scafctl auth handlers                # official handlers (openshift is catalog-resolved on demand)
scafctl catalog list --kind auth-handler   # openshift appears here (local catalog)
```

## 1. Login

```bash
scafctl kube login "$CLUSTER1"       # browser OAuth; writes a kubeconfig context
scafctl kube login "$CLUSTER2"       # a second cluster, for multi-cluster checks
```

Expected: `Logged in to "<CLUSTER1>"`, user `$USER_EMAIL`.

Fixed callback port (optional):

```bash
scafctl auth login openshift --hostname "$CLUSTER1" --callback-port 8400
```

Expected: the OAuth loopback binds port 8400; login succeeds.

## 2. Status and inspection

```bash
scafctl auth status openshift        # one row per cluster, active marked, per-cluster expiry
scafctl auth status openshift -o json
scafctl auth list openshift          # cached token inventory (user logins + SA tokens)
scafctl auth handlers openshift      # handler details and capabilities
```

Expected: `auth status` lists each logged-in cluster (e.g. `$CLUSTER1`,
`$CLUSTER2`), one as `(active)`, with status `authenticated` and a `~24h` expiry.

## 3. Credential helper (oc / kubectl)

```bash
oc --context "$CLUSTER1" whoami      # -> $USER_EMAIL
oc --context "$CLUSTER2" whoami      # -> $USER_EMAIL  (both clusters, simultaneously)
oc --context "$CLUSTER1" get projects
oc config get-contexts               # list contexts
oc config use-context "$CLUSTER1"    # set default context for bare `oc`
```

Expected: `whoami` returns your identity on each cluster. scafctl is invoked as
the exec credential plugin transparently.

## 4. Service-account tokens (Kubernetes TokenRequest)

```bash
# scope is <namespace>/<serviceaccount>
scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA"
scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA" --decode
scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA" -o json
scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA" --force-refresh
scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA@<audience>"
```

Prove the token actually works:

```bash
oc --context "$CLUSTER1" \
  --token="$(scafctl auth token openshift --server "$CLUSTER1" --scope "$NS_SA" --raw)" \
  whoami
# -> system:serviceaccount:<namespace>:<serviceaccount>
```

Notes:
- `--server` accepts a cluster alias (e.g. `$CLUSTER1`) or a full URL (`$SERVER1`).
- A `403 ... cannot create resource "serviceaccounts/token"` means the token
  path works; you simply lack RBAC in that namespace.

## 5. Logout

```bash
scafctl kube logout "$CLUSTER1"      # remove CLUSTER1's kubeconfig entry + clear its credentials
scafctl auth logout openshift        # clear all cached openshift credentials
```

Re-check:

```bash
scafctl auth status openshift        # cleared cluster(s) no longer authenticated
```

## 6. Troubleshooting

```bash
scafctl auth diagnose                # auth health checks / report issues
scafctl auth status openshift -o json
scafctl auth token openshift --server "$CLUSTER1" --decode   # inspect token claims/expiry
scafctl kube login "$CLUSTER1" --log-level debug             # verbose login trace
oc --context "$CLUSTER1" whoami --v=8                          # oc verbose HTTP trace
```

Common errors:

| Symptom | Meaning / fix |
| --- | --- |
| `Unable to connect ... no such host` | DNS/VPN - not on the network that resolves the cluster hostname. Auth is fine; the endpoint is unreachable. |
| `token expired` in `auth status` | OpenShift OAuth tokens are ~24h with no refresh. Run `scafctl kube login <cluster>` again. |
| `unknown cluster "<name>"` | Name is not in your `kube.clusters` resolver/aliases. Use the full `--server https://...` URL or fix config. |
| `--scope is required for ... openshift` | Old scafctl without the exec-scope fix. |
| `403 ... serviceaccounts/token` | RBAC: the token path works, you lack permission in that namespace. |

## Results

| # | Check | Pass/Fail |
| --- | --- | --- |
| 1 | `kube login` (browser OAuth) | |
| 2 | Fixed `--callback-port` binds the requested port | |
| 3 | `auth status` shows per-cluster rows + active | |
| 4 | `oc whoami` on two clusters simultaneously | |
| 5 | SA token mints and `oc --token whoami` returns the SA | |
| 6 | `--server <alias>` name resolution works | |
| 7 | `kube logout` / `auth logout` clear credentials | |
| 8 | `auth diagnose` reports healthy | |
