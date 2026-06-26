#!/usr/bin/env bash
#
# sign-auth.sh — local EIP-7702 authorization signer for hacked-wallet-recovery.
#
# THE COMPROMISED PRIVATE KEY NEVER LEAVES THIS MACHINE.
# Run this in your OWN terminal. It signs the EIP-7702 authorization for the
# curated delegate using a hardcoded, vetted read RPC per chain, and prints ONLY
# the authorization signature(s). Paste a signature back to the agent — it is safe
# to share: it authorizes only the specific delegate contract, is bound to your
# wallet's current nonce, and cannot be reused.
#
# Key handling: the key is entered at a masked prompt (shown as '*' so you get
# feedback that your paste registered) and is read directly into a variable — it is
# NOT written to your shell history and is never sent to the agent. It is passed to
# `cast` via --private-key, which means it is briefly visible in this machine's
# process list (`ps`) during signing. That is an accepted local-only trade for the
# masked input + clear labeling; the key still never leaves your terminal.
#
# Usage:   ./sign-auth.sh <chainId> [<chainId> ...]
# Example: ./sign-auth.sh 1            # Ethereum
#          ./sign-auth.sh 1 56 100     # Ethereum + BSC + Gnosis
#
# Requires: Foundry (cast).  Install: curl -L https://foundry.paradigm.xyz | bash && foundryup
#
set -euo pipefail

DELEGATE=0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892

# Curated read RPCs — the enforced trust boundary. Keep in sync with
# references/recover-template.ts CHAIN_RPCS and SKILL.md "Supported Chains".
declare -A READ_RPC=(
  [1]="https://ethereum-rpc.publicnode.com"
  [10]="https://optimism-rpc.publicnode.com"
  [56]="https://bsc-rpc.publicnode.com"
  [100]="https://gnosis-rpc.publicnode.com"
  [130]="https://unichain-rpc.publicnode.com"
  [143]="https://rpc.monad.xyz"
  [480]="https://worldchain-mainnet.g.alchemy.com/public"
  [1868]="https://rpc.soneium.org"
  [2020]="https://api.roninchain.com/rpc"
  [5000]="https://mantle-rpc.publicnode.com"
  [8453]="https://base-rpc.publicnode.com"
  [42161]="https://arbitrum-one-rpc.publicnode.com"
  [42220]="https://celo-rpc.publicnode.com"
  [43114]="https://avalanche-c-chain-rpc.publicnode.com"
  [57073]="https://rpc-gel.inkonchain.com"
  [81457]="https://rpc.blast.io"
  [747474]="https://rpc.katana.network"
  [7777777]="https://rpc.zora.energy"
)
declare -A CHAIN_NAME=(
  [1]="Ethereum" [10]="Optimism" [56]="BSC" [100]="Gnosis" [130]="Unichain"
  [143]="Monad" [480]="World" [1868]="Soneium" [2020]="Ronin" [5000]="Mantle"
  [8453]="Base" [42161]="Arbitrum" [42220]="Celo" [43114]="Avalanche"
  [57073]="Ink" [81457]="Blast" [747474]="Katana" [7777777]="Zora"
)

# Read a secret into the named variable, echoing '*' per character (with backspace
# support) so the user gets visual feedback that their paste registered. All prompt
# output goes to stderr; nothing is added to shell history.
read_secret() {
  local __prompt="$1" __dest="$2" __ch __val=""
  printf '%s' "$__prompt" >&2
  while IFS= read -rsn1 __ch; do
    [[ -z "$__ch" ]] && break                       # Enter -> done
    if [[ "$__ch" == $'\177' || "$__ch" == $'\b' ]]; then
      if [[ -n "$__val" ]]; then __val="${__val%?}"; printf '\b \b' >&2; fi
    else
      __val+="$__ch"; printf '*' >&2
    fi
  done
  printf '\n' >&2
  __val="${__val#"${__val%%[![:space:]]*}"}"        # trim leading whitespace
  __val="${__val%"${__val##*[![:space:]]}"}"        # trim trailing whitespace
  printf -v "$__dest" '%s' "$__val"
}

command -v cast >/dev/null 2>&1 || {
  echo "error: Foundry's 'cast' not found." >&2
  echo "       install: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
  exit 1
}

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <chainId> [<chainId> ...]" >&2
  echo "supported chain ids: ${!READ_RPC[*]}" >&2
  exit 1
fi

# Validate every requested chain BEFORE prompting for the key.
for id in "$@"; do
  if [ -z "${READ_RPC[$id]:-}" ]; then
    echo "error: chain $id is not in the curated registry — refusing to sign for an unvetted network." >&2
    echo "       supported chain ids: ${!READ_RPC[*]}" >&2
    exit 1
  fi
done

echo "Paste your COMPROMISED wallet's private key below, then press Enter." >&2
echo "Input is masked (shown as *), is not saved to history, and never goes to the agent." >&2
echo >&2

PRIVATE_KEY=""
read_secret "Private key: " PRIVATE_KEY
[ -n "$PRIVATE_KEY" ] || { echo "error: no key entered" >&2; exit 1; }

# Clear, delineated handoff message so the user does NOT mistake the output below
# for something secret. Everything printed after this banner is shareable.
{
  echo
  echo "════════════════════════════════════════════════════════════════════"
  echo " ✅ Got it. Signing complete."
  echo
  echo " 👉 Now give the signature(s) below back to your agent."
  echo "    These are SAFE to share — each is an authorization signature,"
  echo "    NOT your private key, and contains no secret."
  echo "════════════════════════════════════════════════════════════════════"
} >&2

for id in "$@"; do
  echo >&2
  echo "── chain $id (${CHAIN_NAME[$id]}) — authorization signature ──" >&2
  cast wallet sign-auth "$DELEGATE" --private-key "$PRIVATE_KEY" --rpc-url "${READ_RPC[$id]}"
done

unset PRIVATE_KEY
