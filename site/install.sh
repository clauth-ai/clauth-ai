#!/usr/bin/env bash
set -euo pipefail

# Clauth installer (source install)
# Usage: curl -fsSL https://cl-auth.com/install.sh | bash

BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
RED="\033[31m"
ORANGE="\033[33m"
RESET="\033[0m"

INSTALL_DIR="${CLAUTH_INSTALL_DIR:-$HOME/.clauth-app}"
REPO_URL="${CLAUTH_REPO_URL:-https://github.com/clauth-ai/clauth.git}"
MIN_NODE_MAJOR=22

info()  { printf "${BOLD}${GREEN}=>${RESET} %s\n" "$1"; }
warn()  { printf "${BOLD}${ORANGE}=>${RESET} %s\n" "$1"; }
error() { printf "${BOLD}${RED}=>${RESET} %s\n" "$1" >&2; }
dim()   { printf "${DIM}   %s${RESET}\n" "$1"; }

header() {
  echo ""
  printf "${ORANGE}${BOLD}"
  echo "    ╔═══════════════════════════════════════╗"
  echo "    ║           clauth installer             ║"
  echo "    ║   credential proxy for your agents     ║"
  echo "    ╚═══════════════════════════════════════╝"
  printf "${RESET}"
  echo ""
}

check_node() {
  if ! command -v node &>/dev/null; then
    error "Node.js is not installed."
    dim "Clauth requires Node.js $MIN_NODE_MAJOR or later."
    dim "Install it from https://nodejs.org or via your package manager."
    exit 1
  fi

  local node_version
  node_version=$(node -v | sed 's/^v//')
  local major
  major=$(echo "$node_version" | cut -d. -f1)

  if [ "$major" -lt "$MIN_NODE_MAJOR" ]; then
    error "Node.js $node_version found, but $MIN_NODE_MAJOR+ is required."
    dim "Upgrade from https://nodejs.org or via your package manager."
    exit 1
  fi

  info "Node.js $node_version detected"
}

check_npm() {
  if ! command -v npm &>/dev/null; then
    error "npm is not installed."
    dim "npm should come with Node.js. Try reinstalling Node."
    exit 1
  fi
}

install_clauth() {
  if ! command -v git &>/dev/null; then
    error "git is not installed."
    dim "Install git (or Xcode Command Line Tools on macOS) and re-run."
    exit 1
  fi

  info "Installing clauth from source..."
  if [ -d "$INSTALL_DIR/.git" ]; then
    dim "Updating existing checkout at $INSTALL_DIR"
    git -C "$INSTALL_DIR" pull --ff-only 2>&1 | while IFS= read -r line; do dim "$line"; done
  else
    dim "Cloning into $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR" 2>&1 | while IFS= read -r line; do dim "$line"; done
  fi

  info "Installing dependencies..."
  (cd "$INSTALL_DIR" && npm install) 2>&1 | while IFS= read -r line; do dim "$line"; done
}

post_install() {
  echo ""
  info "Clauth installed successfully!"
  echo ""
  printf "  ${BOLD}Get started:${RESET}\n"
  dim "cd \"$INSTALL_DIR\""
  dim "npm run cli -- init"
  dim "export CLAUTH_PASSPHRASE='your-long-passphrase-here'  # or use CLAUTH_PASSPHRASE_FILE"
  dim "export CLAUTH_ADMIN_TOKEN='set-admin-token'"
  dim "npm run dev"
  echo ""
  printf "  ${BOLD}Notes:${RESET}\n"
  dim "State is stored in \$CLAUTH_HOME (default: \$HOME/.clauth)."
  dim "This installer only sets up the repo checkout at $INSTALL_DIR."
  echo ""
  printf "  ${BOLD}Learn more:${RESET}\n"
  dim "https://cl-auth.com"
  echo ""
}

main() {
  header
  check_node
  check_npm
  install_clauth
  post_install
}

main
