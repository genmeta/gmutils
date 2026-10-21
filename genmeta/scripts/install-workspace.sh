#!/bin/sh
# Best-effort package-install hook. Never leave a retry job or fail gmutils setup.

manual_hint() {
    printf '%s\n' 'gmutils: after configuring a default identity and starting Pishoo, run: genmeta install workspace' >&2
}

cli=${1:-}
if [ -z "$cli" ] || [ ! -x "$cli" ]; then
    printf '%s\n' 'gmutils: Workspace auto-install skipped; genmeta is unavailable.' >&2
    manual_hint
    exit 0
fi

uid=$(id -u 2>/dev/null) || uid=
case "$uid" in
    ''|*[!0-9]*)
        printf '%s\n' 'gmutils: Workspace auto-install skipped; installation user is unknown.' >&2
        manual_hint
        exit 0
        ;;
esac

actor=${SUDO_USER:-}
if [ "$uid" = 0 ] && [ -n "$actor" ] && [ "$actor" != root ]; then
    # DEB/RPM maintainer hooks run as root. When sudo identifies its caller,
    # use that caller's default identity rather than root's.
    actor_uid=$(id -u "$actor" 2>/dev/null) || actor_uid=
    case "$actor_uid" in
        ''|*[!0-9]*|0)
            printf '%s\n' 'gmutils: Workspace auto-install skipped; no invoking user is available.' >&2
            manual_hint
            exit 0
            ;;
    esac
    if ! command -v runuser >/dev/null 2>&1; then
        printf '%s\n' 'gmutils: Workspace auto-install skipped; cannot switch to the installation user.' >&2
        manual_hint
        exit 0
    fi
    if runuser -u "$actor" -- "$cli" install workspace </dev/null; then
        exit 0
    fi
else
    if "$cli" install workspace </dev/null; then
        exit 0
    fi
fi

printf '%s\n' 'gmutils: Workspace auto-install did not complete; gmutils installation succeeded.' >&2
manual_hint
exit 0
