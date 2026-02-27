# Decisions

## 2026-02-27 Session Start
- Use `execute_hyper_request` not `new_request().execute()` for H3 forwarding
- Domain suffix param: `--domain-suffix` with default `.genmeta.net`
- Listen addr default: `127.0.0.1:8080`
- Non-genmeta HTTP forwarding: NO connection pool (per-request connection fine for Phase 1)
- Module split: route.rs, h3_forward.rs, tunnel.rs, forward.rs (separate from lib.rs)
