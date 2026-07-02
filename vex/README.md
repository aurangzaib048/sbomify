# Self-VEX

CycloneDX VEX documents that justify the High/Critical advisories in sbomify's own
components which cannot be cleared by a version bump, so the dashboard reflects
unaddressed risk only.

These are **hand-maintained CycloneDX**, the same model as the CBOM
(`cbom/sbomify-backend.cbom.cdx.json`). There is no intermediate format: the
`*.vex.cdx.json` files here are the source of record and are exactly what ships.
CycloneDX VEX is used (not OpenVEX) because sbomify produces and ingests
CycloneDX and the Dependency-Track / OSV pipeline is CycloneDX-native; OpenVEX
would add a lossy conversion hop.

| File | Subject component |
| --- | --- |
| `frontend-stack.vex.cdx.json` | Frontend Stack (`bun.lock`) |
| `container.vex.cdx.json` | Container image (osv-scanner / cosign tooling) |

## Adding or updating a statement

Edit the relevant `*.vex.cdx.json` directly:

1. Add the affected dependency to `components[]` with a `bom-ref` and `purl`
   (convention: `bom-ref == purl`). **Omit the version from the purl**
   (`pkg:npm/foo`, not `pkg:npm/foo@1.2.3`): the justifications here are about how the
   package is *used*, not which version is present, so a version-less purl keeps the
   statement applying after a release bumps the dependency. Record the version context
   in `detail`, and pin a version only if the justification genuinely holds for that one
   version.
2. Add the statement to `vulnerabilities[]`: the advisory `id`, `ratings`,
   `cwes`, a `description`, `affects[].ref` pointing at the component's `bom-ref`,
   and the human judgment in `analysis` (`state` + `justification` + `detail`).
   `state`/`justification` are the CycloneDX `impactAnalysisState` /
   `impactAnalysisJustification` enums.
3. Bump `metadata.timestamp` (CISA's "last updated").

Look up CVSS / aliases / CWEs from [osv.dev](https://osv.dev) when adding a
statement.

## Checks

`check_self_vex` schema-validates these documents (via sbomify's own CycloneDX
validator) and, given a release's scan, checks the VEX against it with the SAME matcher
the runtime suppression uses — so the CI gate and the dashboard can't disagree:

```sh
uv run python manage.py check_self_vex                               # validate all
uv run python manage.py check_self_vex --findings scan.json          # + drift gate
uv run python manage.py check_self_vex --findings scan.json --strict # fail on stale too
```

The drift gate **fails** on a finding with no matching statement (a new High/Critical
must be triaged) and **warns** — fails under `--strict` — on a statement that matches no
finding in the release (a moot/stale statement to prune). Together these keep the VEX in
step with each release. The schema validation also runs in CI through the test suite.

## Consumption

Uploading a `bom_type=vex` artifact to a component suppresses its `not_affected`
findings from the vulnerability dashboard. Suppression is applied at read time
(`vulnerability_scanning/vex.py`), provider-agnostic (OSV and Dependency-Track),
and never mutates the stored scan result (ADR-004). A finding matches a statement
when their vulnerability ids (or aliases) intersect and they name the same package —
version-agnostic when the statement's purl carries no version, so the suppression
survives a release that bumps the dependency; a different package hit by the same CVE is
not over-suppressed.

## Publishing

`.github/scripts/publish-vex.sh` uploads each document to its component as
`bom_type=vex` via OIDC trusted publishing (the gated `publish-vex` CI jobs).
