# Jade

Create a Pishoo application, run it locally, then build and publish a signed
`.waz` package. This guide uses the example name `alex.chen` (Alex Chen); replace it with your own name.

## Start locally

Install Node.js/npm for the frontend, a Rust toolchain with `wasm32-wasip2` for
the API, and run Pishoo locally.

```sh
jade create hello
cd hello
rustup target add wasm32-wasip2
jade run --id alex.chen
```

This runs on `dev.alex.chen`. If its ordinary identity credentials are missing,
follow Jade's `genmeta identity apply dev.alex.chen` hint, then retry.
Local run needs no developer certificate or subscription.

Open the App URL printed by Jade. Edit `web/index.html`, `web/src/main.js`,
`web/src/style.css` and `api/src/lib.rs`; Jade rebuilds on changes.
Ctrl+C removes this run's local code and keeps development data.

The default template includes an English welcome page with a Chinese language
switch and a GET `/whoami` API. The API reads the verified **visitor's** name;
it can differ from the identity hosting the application. Displayed names omit
`.dhttp.net`; the API returns the full name. Vite alone does not serve this API.

## One name for every Jade command

Use the same `--id alex.chen` for `run`, `build` and `publish`. Jade uses
`dev.alex.chen` internally for local hosting, signing and publication.
Local hosting needs ordinary identity credentials; signing and publication need
developer credentials, which `publish` helps prepare.

Without `--id`, local run uses the DHTTP default name, or `zero.ai`. Build can
also use `package.author` or available developer credentials. `package.author`
is the actual author recorded in the package; if configured, it must match the
selected developer identity. Signed metadata always keeps the full name.

## Publish and install

Start publication from the project directory. Jade guides first-time developer setup:

```sh
jade publish --id alex.chen
```

If there is no built package, follow the build hint after setup:

```sh
jade build --id alex.chen
# Review build/hello-0.1.0.waz before uploading.
jade publish --id alex.chen
```

Setup may require confirming the developer subscription and completing checkout.
With an existing package, Jade prepares missing upload credentials and continues
publication. Without a package, it asks you to build and review one first.
JSON and noninteractive runs report the required next step without starting setup.
Publication never builds or re-signs a package implicitly.

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
Jade discovers frontend and Rust source directories automatically. Signed output
and Cargo's cache go under `build/`. Root `README.md` and `CHANGELOG.md` are included
in the package when present. `--json` produces machine-readable output.

See [the reference](REFERENCE.md) for configuration, local dependencies, credentials,
publication checks and validation commands, or [the WAZ format](FORMAT.md).
