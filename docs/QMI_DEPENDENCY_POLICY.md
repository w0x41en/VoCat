# QMI dependency and open-source policy

VoCat consumes QMI through the maintained MIT fork
[`github.com/w0x41en/quectel-qmi-go`](https://github.com/w0x41en/quectel-qmi-go).
The fork is based on upstream `v0.6.0` and publishes the first maintained
release as `v0.6.0-vocat.1`.

## Repository boundary

- VoCat owns the integration code, modem policy, eSIM orchestration, and
  application behavior.
- The QMI fork owns the reusable QMI transport and service wrappers.
- The old in-tree `third_party/quectel-qmi-go` copy is intentionally removed;
  release builds must resolve the tagged module from `go.mod`.
- No local `replace` directive is allowed in a release branch.

## Attribution and licensing

The QMI fork retains the upstream MIT license and copyright attribution. Its
fork-specific WMS readiness/route wrappers and Qualcomm error-code mapping are
documented in the fork's `NOTICE`, `CHANGELOG.md`, and
`OPEN_SOURCE_POLICY.md`. VoCat's top-level license does not relicense the QMI
fork.

## Upgrade procedure

1. Review the fork's provenance, license, and release notes.
2. Update the pinned version in `go.mod` and run `go mod tidy`.
3. Run `go test ./...`, `go vet ./...`, and a clean-module build without any
   local replacement.
4. For QMI wire/API changes, run sanitized transcript tests and an OpenStick
   smoke test before deployment.
5. Record the change in the VoCat changelog and keep subscriber identifiers,
   APN credentials, raw APDUs, and packet captures out of the repository.

## Compatibility rules

The following are treated as wire/API compatibility contracts and require
regression tests in the QMI fork:

- QMI error mapping (`INVALID_ARG=0x0030`,
  `CARD_CALL_CONTROL_FAILED=0x0060`);
- WMS reset, subscription binding, service readiness, and route TLVs;
- UIM/eUICC file and APDU behavior used by VoCat's identity and SMS paths;
- service allocation and QMI client lifecycle on `/dev/wwanNqmiN`.
