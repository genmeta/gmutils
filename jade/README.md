# Jade

Create a Pishoo application, build it, run it locally, then sign and publish its
`.waz` package. This guide uses the example name `alex.chen` (Alex Chen); replace it with your own name.

## Start locally

Install Node.js/npm for the frontend, a Rust toolchain with `wasm32-wasip2` for
the API, and run Pishoo locally.

```sh
jade create hello
cd hello
rustup target add wasm32-wasip2
jade run --id dev.alex.chen
```

This runs on `dev.alex.chen`. If its ordinary identity credentials are missing,
follow Jade's `genmeta identity apply dev.alex.chen` hint, then retry.
Jade checks these credentials before building or configuring the listener; a
profile directory or unfinished developer request alone is insufficient.
An unfinished developer request does not prevent ordinary identity setup.
Local run needs no developer certificate or subscription.

Open the App URL printed by Jade. Edit `web/index.html`, `web/src/main.js`,
`web/src/style.css` and `api/src/lib.rs`; Jade rebuilds on changes.
Ctrl+C removes this run's local code and keeps development data.

The default template includes an English welcome page with a Chinese language
switch and a GET `/whoami` API. The API reads the verified **visitor's** name;
it can differ from the identity hosting the application. Displayed names omit
`.dhttp.net`; the API returns the full name. Vite alone does not serve this API.

## One name for every Jade command

Use the same `--id dev.alex.chen` for `run`, `build` and `publish`. Jade uses
that exact development identity for local hosting, signing and publication.
Explicit names are never converted by adding or removing `dev.`. A main name
such as
`dev.wang` must be selected as `dev.dev.wang` for development.
Build needs no identity credentials. Local hosting needs ordinary identity
credentials; publication requires `codeSigning`, which `publish` helps prepare.
Both use the certificate and key in the identity's normal `ssl/` directory.
`genmeta identity apply DEV_NAME` requests a new sequence: active developer
entitlement for that bound name selects a developer certificate; otherwise it
selects ordinary TLS credentials. `renew` keeps the installed sequence and purpose.

Without `--id`, local run selects the `dev` child of the DHTTP default name, or
uses `dev.zero.ai` when no default is configured. A default of `dev.wang` selects
`dev.dev.wang`; a default of `dev.dev.wang` stays unchanged. Build uses
`package.author` first, otherwise the same default child or `dev.zero.ai`.
Publication setup uses that same selection when no package author is available.
`package.author` is the actual author recorded in the package; if configured,
it must match the
selected developer identity. Signed metadata always keeps the full name.

## Publish and install

Build and review the package before publishing:

```sh
jade build --id dev.alex.chen
# Review build/hello-0.1.0.waz.
jade run --id dev.alex.chen
# After local testing, stop the watcher with Ctrl+C.
jade publish --id dev.alex.chen
```

Build creates an unsigned package and requires no developer certificate or
subscription. Run also builds from source and watches for changes. Publish reads
the existing build, prepares developer credentials when needed, signs that fixed
content and uploads it. It leaves the local build archive unchanged and never
rebuilds sources. An already signed package is verified and uploaded unchanged.

First-time publication may require confirming the developer subscription and
completing checkout. As with `genmeta identity apply`, Jade shows the
public checkout link and QR code returned by the server; this payment page does
not require another login. Jade waits for confirmed payment with a progress
indicator. The invoice's API URL is used only for status queries.
The wait follows both the payment link and invoice deadlines, up to 15 minutes; retrying preserves the
checkout and pending certificate request. Without a built package, publication
asks you to build and review one first. JSON and noninteractive runs report the required next step
without starting setup.

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
