# Hacked Wallet Recovery (Claude skill)

A [Claude Code](https://claude.com/claude-code) skill for rescuing assets from a
**compromised Ethereum wallet** using [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)
delegation — without ever exposing the compromised private key.

If an attacker has your private key, you can't safely send a normal transaction: the moment
gas hits the wallet, a sweeper bot takes it. This skill coordinates a recovery where the
compromised key is used only to sign a single, harmless authorization locally, and a separate
funded **operator wallet** pays gas and broadcasts an atomic batch transfer of every asset to
a safe address.

## The security model

- **The compromised private key never leaves your terminal.** You run one local signing
  command (`scripts/sign-auth.sh`); it prompts for the key interactively (never in argv or
  shell history) and prints only a signed EIP-7702 authorization hex. That hex is safe to
  share — it authorizes one specific delegate contract, is bound to the current nonce, and
  cannot be reused.
- **A temporary operator wallet broadcasts.** The agent generates it as an encrypted Foundry
  keystore (only the address is ever printed) and you fund it with a small gas float. It signs
  an EIP-712 recovery intent that **binds the destination**, so it can't redirect funds.
- **One atomic transaction** moves all tokens/NFTs and sweeps native ETH to your safe wallet.

| Step | Who acts | Key used |
|------|----------|----------|
| Asset discovery | Agent (RPC reads) | none |
| Generate operator keystore | Agent | none (encrypted at rest) |
| Sign EIP-7702 authorization | **You, locally** | compromised key |
| Sign recovery intent + broadcast | Recovery script | operator key (in-memory) |

## Why private mempools

The authorization is bound to the compromised wallet's current nonce. If an attacker can
*see* the recovery transaction pending, they send one first to bump the nonce and invalidate
it. So the transaction must reach the network unobservable. Each supported chain is classified:

- **`relay`** (Ethereum, BSC, Gnosis) — public mempool; broadcast via a private relay
  (Flashbots / Blinklabs / Shutter).
- **`sequencer`** (Optimism, Base, Arbitrum, and other L2s) — no outsider-queryable mempool;
  any RPC is safe.
- **`unsafe`** (e.g. Celo) — observable mempool, no relay; front-runnable. Gated behind an
  explicit warning + confirmation.

RPCs are **not free-form** — a curated, vetted registry per chain is the enforced trust
boundary, embedded in both the recovery script and the signer.

## Layout

| Path | What it is |
|------|------------|
| `SKILL.md` | The skill itself — full workflow the agent follows |
| `scripts/sign-auth.sh` | Local EIP-7702 signer you run (shell wrapper around Foundry's `cast`) |
| `scripts/check-assets.js` | Zero-dependency ERC-20 / native balance discovery (Node built-in `fetch`) |
| `references/recover-template.ts` | Annotated recovery script template (viem) the agent fills in |
| `references/nft-discovery.md` | Finding NFT token IDs and encoding ERC-721 / ERC-1155 transfers |
| `test/e2e-fork.sh` | End-to-end test against real mainnet delegate bytecode on a local fork |

## Prerequisites

- [Foundry](https://getfoundry.sh) (`cast`) — for the local signing step.
- Node.js v18+ — for the recovery script (one dependency: `viem`).

## Usage

Install as a Claude Code skill and trigger it by describing the situation (e.g. "my wallet
was hacked and I need to move my tokens out"). The agent walks through discovery, operator
setup, gas funding, local signing, and broadcast. See `SKILL.md` for the full flow.

## Disclaimer

Provided as-is for defensive asset recovery. Recovery is a race against the attacker and is
not guaranteed to succeed. Review what the scripts do before running them, and verify every
address. Nothing here is financial or security advice.
