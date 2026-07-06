---
description: "scafctl provider guidance: method responsibilities, schema design, WhatIf parity, configuration, and tests."
applyTo: "**/*.go"
---

# scafctl Provider Guidance

Use this guidance when editing provider plugin code.

## Method Responsibilities

Keep the provider lifecycle methods sharply separated.

- `GetProviderDescriptor` describes the provider contract.
- `ExecuteProvider` performs the real work.
- `DescribeWhatIf` explains what execution would do without side effects.
- `ConfigureProvider` stores host configuration for later use.
- `ExecuteProviderStream` should only be implemented when streaming output is truly supported.
- `ExtractDependencies` should only return resolver dependencies when provider inputs reference them.
- `StopProvider` should be safe and idempotent.

## Descriptor Rules

The descriptor is the source of truth for the provider contract.

- Keep `Name`, `DisplayName`, `Description`, `Capabilities`, `Schema`, and `OutputSchemas` consistent.
- Every declared capability must have a corresponding entry in `OutputSchemas`.
- Do not advertise capabilities that the implementation does not support.
- A descriptor without `OutputSchemas` will fail host registration. The host validates descriptors before making providers available.
- Ensure required schema fields match runtime expectations.
- Keep examples realistic and aligned with README snippets and tests.

## OutputSchemas Contract

`OutputSchemas` maps each declared capability to a JSON Schema describing the provider's output shape for that capability.

- The map key must be a `sdkprovider.Capability` constant (e.g., `sdkprovider.CapabilityFrom`).
- Every capability listed in `Capabilities` must appear in `OutputSchemas`.
- Missing `OutputSchemas` causes the host to reject the provider at registration time. The user-facing error is `provider not found` because the provider never registers.
- Use `sdkhelper.ObjectSchema` to define output shapes consistently.
- Keep output field names stable across versions.

### Required Output Fields Per Capability (SDK v0.11.0)

SDK v0.11.0 `provider.ValidateDescriptor` enforces required output fields and
their JSON Schema types for each declared capability. A descriptor that omits a
required field (or uses the wrong type) fails validation and the provider does
not register. The supported capabilities are `from`, `transform`, `validation`,
`authentication`, `action`, `state`, and `kubeconfig`.

| Capability | Required output fields |
| --- | --- |
| `from` / `transform` | none |
| `action` / `state` / `kubeconfig` | `success` (boolean) |
| `validation` | `valid` (boolean), `errors` (array) |
| `authentication` | `authenticated` (boolean), `token` (string) |

Providers may add extra fields (e.g., `data` alongside `success`), but the
required fields above must be present with the correct types.

## Provider Name vs Binary Name

- The provider identity comes from the provider name returned over RPC and the published plugin or catalog name, not from the exact binary filename.
- `GetProviders` should return the provider name users reference in solutions.
- `GetProviderDescriptor("name")` should describe that same provider name.
- The executable only needs to be runnable. On Windows that means it must end in `.exe`.
- Prefer binary names like `scafctl-plugin-<provider>` or `scafctl-plugin-<provider>.exe`, but treat that as convention, not a resolution rule.
- Do not rely on the filename alone to make `provider:<name>` resolve.

## Execution Rules

- Reject unknown provider names consistently across all methods.
- Handle nil, empty, and zero-value inputs deliberately.
- Return structured output with stable field names.
- Avoid hidden global state and cross-call mutation.
- Wrap non-trivial errors with context.

## WhatIf Rules

`DescribeWhatIf` should be useful and trustworthy.

- Describe the same operation that `ExecuteProvider` would perform.
- Do not perform I/O, mutation, or other side effects.
- Mention important inputs when they affect behavior.
- Keep wording specific enough to help a reviewer verify intent.

## Configuration Rules

- Read host-provided settings through `ConfigureProvider`.
- Keep configuration validation close to where values are consumed.
- Do not hardcode secrets, tokens, URLs, or file system assumptions.

## Test Expectations

Every provider change should consider tests for:

- known provider vs unknown provider
- happy path execution
- invalid, nil, or empty input
- descriptor validity and `OutputSchemas` coverage for all capabilities
- `DescribeWhatIf` parity with execution intent
- configuration-dependent behavior
- any new edge case introduced by the change