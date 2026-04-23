#!/usr/bin/env bash
# setup-user-env-linux.sh — guided installer for per-user CA trust env vars.
#
# Linux has no user-writable system CA store. This script sets the three
# environment variables that most runtimes (Node.js, Python/requests, curl)
# and indirectly Go (via SSL_CERT_FILE) honour for custom CA bundles:
#
#   NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, SSL_CERT_FILE
#
# Targets:
#   ~/.config/environment.d/ai-proxy.conf  (always — picked up by systemd)
#   Shell rc file (opt-in — detected from $SHELL)
#
# Usage:
#   setup-user-env-linux.sh --ca-path /path/to/ca-cert.pem
#   setup-user-env-linux.sh --ca-path /path/to/ca-cert.pem --dry-run
#   setup-user-env-linux.sh --ca-path /path/to/ca-cert.pem --yes
#   setup-user-env-linux.sh --help

set -euo pipefail

# --- Defaults ---
CA_PATH=""
DRY_RUN=false
YES=false
MARKER="# ai-anonymizing-proxy — user CA trust"
CHANGED_FILES=()

# --- Usage ---
usage() {
    cat <<'USAGE'
setup-user-env-linux.sh — set per-user CA trust env vars for the AI proxy.

USAGE:
  setup-user-env-linux.sh --ca-path <path> [--dry-run] [--yes]
  setup-user-env-linux.sh --help

OPTIONS:
  --ca-path <path>   Path to the CA certificate (resolved to absolute).
  --dry-run          Print intended changes without writing anything.
  --yes, -y          Non-interactive — apply all recommended changes.
  --help, -h         Show this help and exit.

TARGETS:
  ~/.config/environment.d/ai-proxy.conf
      Sets NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, SSL_CERT_FILE.
      Picked up by systemd user sessions on next login.

  Shell rc (detected from $SHELL):
      bash  → ~/.bashrc
      zsh   → ~/.zshrc
      fish  → ~/.config/fish/conf.d/ai-proxy.fish

After running, log out and back in (or source the shell rc) for changes
to take effect in new terminals.
USAGE
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-path)
            if [[ $# -lt 2 ]]; then
                echo "Error: --ca-path requires a value." >&2; exit 1
            fi
            CA_PATH="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --yes|-y)
            YES=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

if [[ -z "$CA_PATH" ]]; then
    echo "Error: --ca-path is required." >&2
    echo "Run with --help for usage." >&2
    exit 1
fi

# Check existence before resolving (avoids cryptic cd error for bad directories)
if [[ ! -f "$CA_PATH" ]]; then
    echo "Error: CA certificate not found: $CA_PATH" >&2
    exit 1
fi

# Resolve to absolute path
CA_PATH="$(cd "$(dirname "$CA_PATH")" && pwd)/$(basename "$CA_PATH")"

# --- Helpers ---
confirm() {
    if $YES; then
        return 0
    fi
    local prompt="$1 [y/N] "
    local reply
    read -rp "$prompt" reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# --- Step 1: ~/.config/environment.d/ai-proxy.conf ---
ENV_DIR="$HOME/.config/environment.d"
ENV_FILE="$ENV_DIR/ai-proxy.conf"
ENV_CONTENT="NODE_EXTRA_CA_CERTS=$CA_PATH
REQUESTS_CA_BUNDLE=$CA_PATH
SSL_CERT_FILE=$CA_PATH"

step1_env_conf() {
    echo ""
    echo "=== Step 1: systemd environment.d ==="
    echo "Target: $ENV_FILE"
    echo ""

    if [[ -f "$ENV_FILE" ]]; then
        existing_path=$(sed -n 's/^NODE_EXTRA_CA_CERTS=//p' "$ENV_FILE" 2>/dev/null || true)
        if [[ "$existing_path" == "$CA_PATH" ]]; then
            echo "Already set up with the same CA path. Skipping."
            return
        fi
        echo "File exists with a different CA path:"
        echo "  Current:  $existing_path"
        echo "  Proposed: $CA_PATH"
        echo ""
        echo "Proposed content:"
        echo "$ENV_CONTENT"
        echo ""
        if $DRY_RUN; then
            echo "[dry-run] Would overwrite $ENV_FILE"
            return
        fi
        if ! confirm "Overwrite $ENV_FILE?"; then
            echo "Skipped."
            return
        fi
    else
        echo "Proposed content:"
        echo "$ENV_CONTENT"
        echo ""
        if $DRY_RUN; then
            echo "[dry-run] Would create $ENV_FILE"
            return
        fi
        if ! confirm "Create $ENV_FILE?"; then
            echo "Skipped."
            return
        fi
    fi

    mkdir -p "$ENV_DIR"
    printf '%s\n' "$ENV_CONTENT" > "$ENV_FILE"
    echo "Written: $ENV_FILE"
    CHANGED_FILES+=("$ENV_FILE")
}

# --- Step 2: Shell rc ---
detect_shell_target() {
    local shell_name
    shell_name="$(basename "${SHELL:-}")"
    case "$shell_name" in
        bash) echo "$HOME/.bashrc" ;;
        zsh)  echo "$HOME/.zshrc" ;;
        fish) echo "$HOME/.config/fish/conf.d/ai-proxy.fish" ;;
        *)    echo "" ;;
    esac
}

shell_block_posix() {
    cat <<EOF
$MARKER
export NODE_EXTRA_CA_CERTS="$CA_PATH"
export REQUESTS_CA_BUNDLE="$CA_PATH"
export SSL_CERT_FILE="$CA_PATH"
EOF
}

shell_block_fish() {
    cat <<EOF
$MARKER
set -gx NODE_EXTRA_CA_CERTS "$CA_PATH"
set -gx REQUESTS_CA_BUNDLE "$CA_PATH"
set -gx SSL_CERT_FILE "$CA_PATH"
EOF
}

step2_shell_rc() {
    echo ""
    echo "=== Step 2: Shell rc ==="

    local shell_name
    shell_name="$(basename "${SHELL:-}")"
    local target
    target="$(detect_shell_target)"

    if [[ -z "$target" ]]; then
        echo "Warning: unrecognised shell '$shell_name'. Skipping shell rc setup."
        echo "You can manually export the env vars in your shell config."
        return
    fi

    echo "Detected shell: $shell_name"
    echo "Target: $target"
    echo ""

    # Idempotence check — also detect stale CA path
    if [[ -f "$target" ]] && grep -qF "$MARKER" "$target"; then
        if [[ "$shell_name" == "fish" ]]; then
            existing_rc_path=$(sed -n 's/^set -gx NODE_EXTRA_CA_CERTS "\(.*\)"/\1/p' "$target" 2>/dev/null || true)
        else
            existing_rc_path=$(sed -n 's/^export NODE_EXTRA_CA_CERTS="\(.*\)"/\1/p' "$target" 2>/dev/null || true)
        fi
        if [[ "$existing_rc_path" == "$CA_PATH" ]]; then
            echo "Marker already present in $target with correct CA path. Skipping."
            return
        fi
        echo "Marker present in $target but with a different CA path:"
        echo "  Current:  $existing_rc_path"
        echo "  Proposed: $CA_PATH"
        echo ""
        if $DRY_RUN; then
            echo "[dry-run] Would replace CA path block in $target"
            return
        fi
        if ! confirm "Replace the existing block?"; then
            echo "Skipped."
            return
        fi
        # Remove old block (marker line + next 3 export/set lines) and re-append
        if [[ "$shell_name" == "fish" ]]; then
            sed -i.bak "/$MARKER/,+3d" "$target" && rm -f "$target.bak"
        else
            sed -i.bak "/$MARKER/,+3d" "$target" && rm -f "$target.bak"
        fi
    fi

    local block
    if [[ "$shell_name" == "fish" ]]; then
        block="$(shell_block_fish)"
    else
        block="$(shell_block_posix)"
    fi

    echo "Proposed block:"
    echo "$block"
    echo ""

    if $DRY_RUN; then
        if [[ "$shell_name" == "fish" ]]; then
            echo "[dry-run] Would create $target"
        else
            echo "[dry-run] Would append to $target"
        fi
        return
    fi

    if ! confirm "Apply?"; then
        echo "Skipped."
        return
    fi

    if [[ "$shell_name" == "fish" ]]; then
        mkdir -p "$(dirname "$target")"
        printf '%s\n' "$block" > "$target"
        echo "Written: $target"
    else
        printf '\n%s\n' "$block" >> "$target"
        echo "Appended to: $target"
    fi
    CHANGED_FILES+=("$target")
}

# --- Run ---
step1_env_conf
step2_shell_rc

# --- Summary ---
echo ""
echo "=== Summary ==="
if $DRY_RUN; then
    echo "Dry run complete. No files were modified."
else
    if [[ ${#CHANGED_FILES[@]} -eq 0 ]]; then
        echo "No changes were made (already set up or skipped)."
    else
        echo "Files changed:"
        for f in "${CHANGED_FILES[@]}"; do
            echo "  $f"
        done
        echo ""
        echo "Log out and back in, or source your shell rc, for changes to take effect."
    fi
fi
