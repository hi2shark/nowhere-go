# Security Policy

## Supported versions

Security fixes are provided for the latest v0.3 preview. Earlier pseudo-versions are unsupported after host adapters migrate.

## Reporting

Do not file public issues for authentication bypasses, resource-exhaustion paths, allocation bombs, or connection ownership vulnerabilities. Report them privately to the repository maintainers with a minimal reproducer, affected commit, and expected impact.

The library intentionally returns generic authentication failures to peers. Detailed causes are local diagnostic events only.
