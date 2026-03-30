# Contributing

Thanks for your interest in contributing to the AI Anonymizing Proxy.

## Getting started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the full check suite: `make check`
5. Open a pull request against `main`

## Development workflow

Build, test, lint, and security scanning instructions are in
[docs/development.md](docs/development.md). The key commands:

```bash
make build       # compile
make check       # lint + test + security + vulncheck (must pass before PR)
go test -race ./...  # race detector
```

## Code quality

- All code must pass `golangci-lint` with the project's `.golangci.yml` configuration
- Tests must accompany new functionality
- Coverage must stay above 85% overall
- Security-sensitive paths require 100% coverage

## Adding PII detection patterns

New patterns go in `internal/anonymizer/packs/`. Each pack is a self-contained
file that self-registers via `init()`. Every pattern must include a source comment
linking to the specification or reference it was derived from. See existing packs
for the expected structure.

Test sets for each pack are documented in `docs/test-plans/`.

## Reporting issues

Use GitHub Issues. If reporting a false positive or false negative in PII detection,
include a minimal reproduction string (with synthetic data, never real PII).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
