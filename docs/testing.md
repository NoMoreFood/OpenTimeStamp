# Testing

## Automated Regression Suite

The standard build runs the discoverable MSTest suite and the deployment and
packaging regression suite after compilation:

```powershell
.\build\Build.ps1 -Configuration Debug
```

Use `-SkipTests` only when a compile-only diagnostic is intentional.

## Product Signing Interoperability

On a Windows client with PowerShell 7.6, run this from the repository root:

```cmd
tests\ProductSigning\Run-Tests.cmd
```

The harness creates, signs, timestamps, and verifies representative Word, Excel
VBA, PDF, PowerShell, and EXE artifacts. Missing products are skipped. The Word
test uses its native signing dialog; pass `-NonInteractive` to skip that one
test. A run fails when no selected test passes. Pass
`-RequireAllSelectedTests` (alias `-Strict`) when any skipped selected test must
also fail, as in release qualification.

See the [detailed product-signing test guide](../tests/ProductSigning/README.md)
for prerequisites, URL overrides, certificate handling, and the exact
verification performed for each format.
