# Release Process

This document outlines the steps to cut a new release of sbomify.

## Versioning

sbomify uses [CalVer](https://calver.org/) in the **`YY.MM.MICRO`** format, per
[ADR-0002](https://github.com/sbomify/adr/blob/master/0002-adopt-calver-versioning.md):

- **YY** — two-digit calendar year (`26`, `27`…).
- **MM** — month of release, `1`–`12`, **not zero-padded** (`26.7.0`, never
  `26.07.0`). Leading zeros are invalid SemVer — npm rejects them — and PEP 440
  normalizes `26.07` → `26.7`, so the month must be written unpadded.
- **MICRO** — release counter within the month, starting at `0`. The first
  release in a month is `.0`; subsequent releases that month (features or
  fixes) increment it: `26.7.0`, `26.7.1`, `26.7.2`.

So the first release cut in July 2026 is `26.7.0`; a September 2026 release is
`26.9.0`; the first release of 2027 is `27.<month>.0`. A skipped month simply
leaves a gap in the sequence, which is expected.

## Steps

1. Run pre-release checks:

```bash
# Run linting
uv run ruff check .
uv run ruff format --check .
bun markdownlint "**/*.md" --ignore node_modules

# Run tests and coverage
uv run coverage run -m pytest
uv run coverage report
```

Ensure all tests pass, coverage is at least 80%, and there are no linting errors.

1. Determine the new version from the current year/month (`YY.MM.MICRO`, month
   unpadded — see [Versioning](#versioning) above).

1. Bump the version to match in **both** manifests, then refresh the lockfile:

```bash
# Edit the version field in pyproject.toml AND package.json (keep them in sync)
uv lock                       # updates the sbomify entry in uv.lock
```

1. Update `CHANGELOG.md`: move the `[Unreleased]` entries under a new
   `## [YY.MM.MICRO] - <date>` heading.

1. Get the new version number:

```bash
grep '^version = ' pyproject.toml | cut -d'"' -f2
```

1. Create and push a new git tag:

```bash
# Replace YY.MM.MICRO with the version from the previous step
git tag -a vYY.MM.MICRO -m "Release version YY.MM.MICRO"
git push origin vYY.MM.MICRO
```

## Example

For the first release cut in July 2026 (previous release was `26.3.0`):

```bash
# Run pre-release checks
uv run ruff check .
uv run ruff format --check .
bun markdownlint "**/*.md"
uv run coverage run -m pytest
uv run coverage report

# Bump version to 26.7.0 in pyproject.toml and package.json, then:
uv lock

# Get version for tag
VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)

# Create and push tag
git tag -a v${VERSION} -m "Release version ${VERSION}"
git push origin v${VERSION}
```

## Notes

- Always ensure all tests pass before cutting a release
- Keep `pyproject.toml` and `package.json` versions in sync
- Update the changelog if one exists
- Consider creating a GitHub release with release notes
