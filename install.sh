#!/usr/bin/env bash
# recon-orchestrator — interactive install wizard with scope.yaml generation.
set -euo pipefail

if [ -t 1 ]; then C_BOLD="$(tput bold)"; C_RESET="$(tput sgr0)"; C_GREEN="$(tput setaf 2)"; C_YELLOW="$(tput setaf 3)"; C_RED="$(tput setaf 1)"; else C_BOLD=""; C_RESET=""; C_GREEN=""; C_YELLOW=""; C_RED=""; fi
say()  { printf "%s%s%s\n" "$C_BOLD" "$1" "$C_RESET"; }
info() { printf "  %s\n" "$1"; }
ok()   { printf "  %s✓%s %s\n" "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf "  %s!%s %s\n" "$C_YELLOW" "$C_RESET" "$1"; }
fail() { printf "  %s✗%s %s\n" "$C_RED" "$C_RESET" "$1" >&2; exit 1; }
prompt_yn() { local q="$1" def="${2:-y}" ans; if [ "$def" = "y" ]; then read -r -p "  $q [Y/n]: " ans; ans="${ans:-y}"; else read -r -p "  $q [y/N]: " ans; ans="${ans:-n}"; fi; [[ "$ans" =~ ^[Yy] ]]; }
prompt_default() { read -r -p "  $1 [$2]: " ans; echo "${ans:-$2}"; }

detect_os() { OS_ID=unknown; OS_LIKE=""; OS_VERSION=""; OS_WSL=0; [ -f /etc/os-release ] && { . /etc/os-release; OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_VERSION="${VERSION_ID:-}"; }; [ "$(uname)" = "Darwin" ] && OS_ID=macos; grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null && OS_WSL=1 || true; }
pkg_install() {
    case "$OS_ID" in
        debian|ubuntu) sudo apt-get update -qq && sudo apt-get install -y "$@";;
        fedora|rhel|centos) sudo dnf install -y "$@";;
        arch|manjaro) sudo pacman -S --noconfirm "$@";;
        alpine) sudo apk add --no-cache "$@";;
        opensuse*|sles) sudo zypper install -y "$@";;
        macos) brew install "$@";;
        *) warn "unknown OS — install manually: $*"; return 1;;
    esac
}
ensure_go() {
    command -v go >/dev/null && { ok "Go: $(go version | awk '{print $3}')"; return 0; }
    if prompt_yn "Install Go via system package manager?"; then
        pkg_install go || pkg_install golang || pkg_install golang-go || fail "Go install failed"
    else fail "Go 1.22+ required"; fi
}

main() {
    say "recon-orchestrator — install wizard (Go MCP server)"
    detect_os
    info "OS: ${OS_ID}${OS_VERSION:+ $OS_VERSION}$([ "$OS_WSL" = 1 ] && echo ' (WSL2)')"
    warn "This tool is for AUTHORIZED testing only."
    if ! prompt_yn "Confirm you have written authorization for any target you will scan?" n; then
        fail "aborted — authorization is mandatory"
    fi

    say ""; say "Step 1/4: Go toolchain"; ensure_go

    say ""; say "Step 2/4: Optional ProjectDiscovery binaries (the things this orchestrator wraps)"
    info "These are AVAILABLE through your package manager on most distros, OR via 'go install':"
    info "    naabu, ffuf — implemented wrappers in v0.1"
    info "    katana, gau, dalfox, arjun, cdncheck, interactsh — stubs (returns helpful error)"
    if prompt_yn "Install naabu + ffuf via 'go install' now?" y; then
        go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || warn "naabu install failed"
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || warn "ffuf install failed"
    fi

    say ""; say "Step 3/4: Build + install MCP server"
    local INSTALL_HOME BIN_DIR
    INSTALL_HOME="$(prompt_default "Install root" "$HOME/.local/share/recon-orchestrator")"
    BIN_DIR="$(prompt_default "Binary directory (must be in \$PATH)" "$HOME/.local/bin")"
    mkdir -p "$INSTALL_HOME" "$BIN_DIR"
    if [ -d "$INSTALL_HOME/.git" ]; then ( cd "$INSTALL_HOME" && git pull -q ); else git clone -q https://github.com/M00C1FER/recon-orchestrator.git "$INSTALL_HOME"; fi
    ( cd "$INSTALL_HOME" && go build -o "$BIN_DIR/recon-orchestrator" ./cmd/recon-orchestrator )
    ok "binary at $BIN_DIR/recon-orchestrator"

    say ""; say "Step 4/4: Generate scope.yaml (authorization interlock)"
    local CFG_DIR CFG_FILE; CFG_DIR="$(prompt_default "scope directory" "$HOME/.config/recon-orchestrator")"
    mkdir -p "$CFG_DIR"; CFG_FILE="$CFG_DIR/scope.yaml"
    if [ -f "$CFG_FILE" ] && ! prompt_yn "$CFG_FILE exists. Overwrite?" n; then
        info "keeping existing scope.yaml"
    else
        local engagement targets oos roe_email today bounty maxrps browser
        engagement="$(prompt_default "Engagement name (e.g., HackerOne — example-corp)" "TODO — fill in before use")"
        echo "  Targets: comma-separated list (use *.example.com for wildcards)"
        targets="$(prompt_default "Targets" "example.com")"
        oos="$(prompt_default "Out-of-scope (optional, comma-separated)" "")"
        roe_email="$(prompt_default "ROE accepted by (your email/handle)" "TODO@example.com")"
        today="$(date -u +%Y-%m-%d)"
        bounty="$(prompt_default "Bounty platform (hackerone|bugcrowd|private)" "private")"
        maxrps="$(prompt_default "Max requests/sec per tool" "5")"
        browser="$(prompt_default "Allow Tier-3 browser tools? (true/false)" "false")"
        {
          echo "engagement: \"$engagement\""
          echo "targets:"
          IFS=',' read -ra arr <<< "$targets"
          for t in "${arr[@]}"; do echo "  - $(echo "$t" | xargs)"; done
          if [ -n "$oos" ]; then
            echo "out_of_scope:"
            IFS=',' read -ra arr <<< "$oos"
            for t in "${arr[@]}"; do echo "  - $(echo "$t" | xargs)"; done
          fi
          echo "roe_accepted: true"
          echo "roe_accepted_by: \"$roe_email\""
          echo "roe_accepted_date: \"$today\""
          echo "bounty: $bounty"
          echo "max_rps: $maxrps"
          echo "browser_allowed: $browser"
        } > "$CFG_FILE"
        ok "scope written to $CFG_FILE"
    fi

    say ""
    ok "Done. Start the server with:"
    info "  recon-orchestrator -scope $CFG_FILE -addr 127.0.0.1:8092"
}
main "$@"
