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
# Key handling: the key is entered at `cast`'s own interactive prompt (-i), which
# reads it directly from the terminal. It is therefore NEVER passed as a command
# argument — it does not appear in your shell history OR in this machine's process
# list (`ps`), and it never reaches the agent. Input is hidden as you type (no
# characters appear — this is expected). You are prompted once per chain.
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

# Up-front explanation so the user knows what to expect and does NOT mistake the
# printed signature for a secret. All guidance goes to stderr; only signatures go
# to stdout.
{
  echo "You'll be asked to paste your COMPROMISED wallet's private key (once per chain)."
  echo "  • Input is HIDDEN — no characters appear as you paste. That is expected, not an error."
  echo "  • What gets printed afterward is an AUTHORIZATION SIGNATURE."
  echo "  • Those signatures are SAFE to share — give them to your agent. They are NOT your key."
} >&2

for id in "$@"; do
  echo >&2
  echo "════════════════════ chain $id (${CHAIN_NAME[$id]}) ════════════════════" >&2
  # -i / --interactive: cast prompts for the key on the terminal — never in argv,
  # shell history, or the process list.
  cast wallet sign-auth "$DELEGATE" --interactive --rpc-url "${READ_RPC[$id]}"
  echo "↑ Authorization signature for chain $id — SAFE to share. Give this line to your agent." >&2
done
