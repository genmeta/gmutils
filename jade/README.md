# Jade

Dependencies contain only an exact `name` and `version`; local Jade declarations
may also set `path`, which is omitted from the release. The store resolves each
package name to its unique author. A name stays reserved after withdrawal.
Cross-author name claims return `409 package_name_conflict`; every repeated
version upload, including identical bytes, returns `409 package_version_conflict`.
Historical signed dependencies with authors remain readable without rewriting packages.

Create a Pishoo application, build it, run it locally, then sign and publish its
`.waz` package. This guide uses the example name `alex.chen` (Alex Chen); replace it with your own name.

## Start locally

Install Node.js/npm for the frontend, a Rust toolchain with `wasm32-wasip2` for
the API, and run Pishoo locally.

```sh
jade create hello
cd hello
rustup target add wasm32-wasip2
jade run
```

Run and build use `package.author` when configured. Otherwise they use the
`dev` child of your DHTTP default name, retaining an existing development child.
For example, a default of `alex.chen` selects `dev.alex.chen`. If neither author
nor default is configured, set one before running or building; Jade does not
invent a fallback identity.

If the selected identity lacks ordinary hosting credentials, follow Jade's
`genmeta identity apply NAME` hint, then retry. Jade checks these credentials
before building or configuring the listener. A profile directory or unfinished
developer request alone is insufficient. Local run needs no developer certificate
or subscription.

Open the App URL printed by Jade. Edit `web/index.html`, `web/src/main.js`,
`web/src/style.css` and `wasm/src/lib.rs`; Jade rebuilds on changes.
Ctrl+C removes this run's local code and keeps development data.

The default template includes an English welcome page with a Chinese language
switch and a GET `/whoami` API. The API reads the verified **visitor's** name;
it can differ from the identity hosting the application. Displayed names omit
`.dhttp.net`; the API returns the full name. Vite alone does not serve this API.

## One identity for run and build

Jade commands have no `--id` option. Run and build use the same rule:

| Configuration | Author and local host |
| --- | --- |
| `package.author` is set | That exact name |
| No author; DHTTP default is a main name | Its `dev` child |
| No author; default is already a development child | The default itself |
| No author or default | `E_IDENTITY_REQUIRED`; configure one |

For example, default `dev.wang` selects `dev.dev.wang`. A configured author is
never rewritten by adding or removing `dev.`. Short and full names are equivalent.
To fix the author and host, add this to the existing `[package]` table:

```toml
author = "dev.alex.chen"
```

`jade create` accepts no identity, writes no author and reads no credentials.
Without an author, run and build use your configured default development identity.
Build writes the chosen author into the WAZ without writing it back to `jade.toml`.
Run watches a separate local snapshot and does not create or modify a release WAZ.
A visitor can use a different client identity to test the application.

Publish uses the existing WAZ's author, even if your default has since changed.
Project publication checks a configured author, name and version against that WAZ.
An explicit `jade publish FILE.waz` uses only that file and does not read a project.

Human output shows the actual author, for example `dev.genmeta.tech~/workspace`.
Only the historical `std.dhttp.net` author is abbreviated as `std/workspace`.

Build needs no identity credentials. Local hosting needs ordinary identity
credentials; publication requires `codeSigning`, which `publish` helps prepare.
Both use the certificate and key in the selected identity's normal `ssl/` directory.
`genmeta identity apply DEV_NAME` requests a new sequence: active developer
entitlement for that bound name selects a developer certificate; otherwise it
selects ordinary TLS credentials. `renew` keeps the installed sequence and purpose.

## Publish and install

Build and review the package before publishing:

```sh
jade run
# After local testing, stop the watcher with Ctrl+C.
jade build
# Review build/hello-0.1.0.waz.
jade publish
```

Build creates an unsigned package and requires no developer certificate or
subscription. Run also builds from source and watches for changes. Publish reads
the existing build, prepares developer credentials when needed, signs that fixed
content, saves the signed WAZ and uploads it without rebuilding sources.
An already signed package is verified and uploaded unchanged. After source
changes and local testing, run build again before publishing those changes.

First-time publication may require confirming the developer subscription and
completing checkout. As with `genmeta identity apply`, Jade shows the
public checkout link and QR code returned by the server; this payment page does
not require another login. Jade waits for confirmed payment with a progress
indicator. The invoice's API URL is used only for status queries.
The wait follows both the payment link and invoice deadlines, up to 15 minutes.
Initial application keeps its key and CSR only in memory; a new invocation creates
a fresh request. It creates no `code-signing/` directory or pending apply file. Without a built package, publication
asks you to build and review one first. JSON and noninteractive runs report the required next step
without starting setup. With no package, interactive setup uses the configured
author or default development identity, then asks you to build, review and publish.
With a package, setup prepares credentials for its recorded author.

Interactive publication shows progress during email verification, developer setup
and upload, followed by a compact publication result. Use `--verb` for detailed
package metadata and SHA256 digests, or `--json` for the complete machine result.

When publication needs a certificate, `jade publish` prompts you to apply for
one and guides the account and subscription checks. Renew an installed developer
identity with `genmeta identity renew dev.alex.chen` before expiry.

To install the published application on your base identity's Pishoo service:

```sh
genmeta install dev.alex.chen/hello --id alex.chen
genmeta curl --id alex.chen https://alex.chen.dhttp.net/hello/whoami
# {"name":"alex.chen.dhttp.net"}
```

Apps use `/app/hello/`; ordinary APIs use `/hello/...`.

## Project options

```sh
jade create website --template static
jade create frontend --template web
jade create service --template api
jade create hello --template fullstack  # Default
```

`jade.toml` contains package metadata and optional exact runtime dependencies.
Jade discovers frontend and Rust source directories automatically. Build output
and Cargo's cache go under `build/`. Root `README.md` and `CHANGELOG.md` are included
in the package when present. `--json` produces machine-readable output.

See [the reference](REFERENCE.md) for configuration, local dependencies, credentials,
publication checks and validation commands, or [the WAZ format](FORMAT.md).
