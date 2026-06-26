---
name: hacked-wallet-recovery
description: Recover assets from a compromised/hacked Ethereum wallet using EIP-7702 delegation. Use this skill whenever someone says their wallet was hacked, drained, or compromised; when they need to rescue tokens or NFTs from a wallet an attacker has access to; when they mention a sweeper bot, MEV bot, or drainer script; when they want to move assets out of a wallet whose private key may be exposed; or when they ask about recovering from a seed phrase leak. The skill coordinates a trustless recovery where the user's compromised private key NEVER leaves their terminal — they run one signing command locally, and the agent handles all discovery, transaction construction, and broadcasting using a temporary operator wallet it generates.
---

# Hacked Wallet Recovery

## How It Works

EIP-7702 lets a transaction include an `authorizationList` — a signed payload that grants a smart contract's code to run inside an EOA for one transaction. The `UniversalRecoveryDelegate` contract (deployed on all major EVM chains) uses this to execute any batch of asset transfers from the compromised wallet in a single atomic transaction.

The transaction is sent and gas is paid by a **temporary operator wallet** the agent generates — not the compromised wallet. The user's compromised private key is used only to produce the EIP-7702 authorization, which they run as a local command. The key is never typed into a prompt or sent anywhere.

**Why a temporary operator wallet (and not the user's browser wallet)?** Recovery requires broadcasting an EIP-7702 type-4 transaction that carries the *compromised* EOA's authorization. A browser wallet (MetaMask, Rabby, etc.) can sign and send a type-4 transaction for its *own* account, but it cannot sign a standalone 7702 authorization, and it cannot broadcast a type-4 transaction carrying a *third party's* authorization. So a funded key must live inside the recovery script — that is the operator wallet. It only ever holds a small gas float, and the EIP-712 recovery intent it signs binds the destination, so it cannot redirect funds.

### Security Boundaries

| Step | Who acts | Private key used |
|------|----------|-----------------|
| Asset discovery | Agent queries RPC | None |
| Generate operator keystore | Agent (`cast wallet new`) | None — key encrypted at rest, only the address is printed |
| Sign EIP-7702 authorization | **User runs local command** | Compromised key |
| Sign recovery intent (EIP-712) | `recover.ts` | Operator key, decrypted in-memory from the keystore |
| Broadcast transaction | `recover.ts` | Operator key, decrypted in-memory from the keystore |

The agent never sees the operator private key in plaintext: it generates an encrypted Foundry keystore (which prints only the address), and `recover.ts` decrypts it at runtime from the keystore file plus a password file. No raw key ever appears in the conversation or in the script source.

---

## Why private mempools (network safety)

The recovery transaction carries an EIP-7702 authorization bound to the compromised
wallet's **current account nonce**. If an attacker who still holds the key can *see* the
recovery transaction before it lands, they will send any transaction from that wallet
first. That bumps the nonce, invalidates the authorization, and the attacker keeps the
assets. So the transaction must reach the network **without the attacker being able to
observe it in the mempool**. This is a property of each chain's architecture:

- **`relay` chains** (Ethereum, BSC, Gnosis): have a public, outsider-queryable mempool.
  We MUST broadcast through a private relay (Flashbots / Blinklabs / Shutter) so the
  transaction is hidden until inclusion.
- **`sequencer` chains** (Optimism, Base, Arbitrum, and other L2s): have **no
  outsider-queryable mempool**. A party can query only their *own* pending transactions,
  never the whole pool — so the centralized sequencer is the only observer and the recovery
  is effectively hidden. Safe via any RPC; no relay needed.
- **`unsafe` chains** (e.g. Celo, status unknown): the attacker may be able to watch the
  mempool and no private relay is available. The recovery can be front-run.

The execution RPC is the security-critical choice (a malicious *read* RPC cannot redirect a
signed transaction — the destination is bound in the operator's EIP-712 signature — it can
only cause a revert). To remove this as an attack surface, **RPCs are not free-form**: both
`recover.ts` and `scripts/sign-auth.sh` embed a curated registry (read RPC, execution RPC,
and mempool class per chain). This registry is the enforced trust boundary.

### Enforcement (agent rules)

1. **Never substitute a custom RPC.** Use only the registry. The chains it covers are the
   only chains supported.
2. For `relay` and `sequencer` chains, proceed normally — the registry already selects the
   correct (private, where required) execution RPC.
3. For an `unsafe` chain, **stop and warn the user** before doing anything, in plain terms:
   *"On this network an attacker watching the mempool can see your recovery transaction and
   send one first to bump your wallet's nonce, which invalidates the recovery and keeps the
   assets under their control. We cannot hide the transaction here. Proceed anyway?"* Only
   continue on explicit confirmation, and only then set `ACK_UNSAFE_MEMPOOL = true` in
   `recover.ts` (the script refuses to broadcast on an `unsafe` chain otherwise).
4. For a chain not in the registry, do not recover there until it has been vetted
   (`cast code 0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892 --rpc-url <RPC>` returns code) and
   deliberately added to the registry with a correct mempool class.

---

## Prerequisites

The user needs **Foundry** installed to run the authorization signing command:
```bash
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

The agent needs **Node.js v18+** to run the recovery script (one npm dependency: `viem@^2.44`).

---

## Workflow

### Phase 1 — Understand the Situation

Ask the user:
1. **Compromised wallet address** — the `0x...` address. *Never ask for the private key.*
2. **Safe destination wallet** — where recovered assets should land.
3. **Which chains** — Ethereum, Base, Arbitrum, etc. (can be multiple).
4. **What assets** — ask them to describe what they have. Verify on-chain.

Use the bundled asset discovery script for a fast sweep of native + common ERC-20 tokens:

```bash
# Audit native balance + all well-known tokens on mainnet.
# Use the curated read RPC for the target chain (see Supported Chains).
node scripts/check-assets.js <COMPROMISED> https://ethereum-rpc.publicnode.com mainnet

# Other network shorthands: base, arbitrum, optimism
node scripts/check-assets.js <COMPROMISED> https://base-rpc.publicnode.com base

# Specific token addresses only
node scripts/check-assets.js <COMPROMISED> <RPC_URL> 0xTOKEN1,0xTOKEN2
```

The script outputs balances and generates ready-to-paste CALLS entries for `recover.ts`.

For manual checks or NFTs:

```bash
# Native balance
cast balance <COMPROMISED> --rpc-url <RPC_URL>

# ERC-20 balance
cast call <TOKEN> "balanceOf(address)(uint256)" <COMPROMISED> --rpc-url <RPC_URL>

# ERC-721 ownership
cast call <NFT> "ownerOf(uint256)(address)" <TOKEN_ID> --rpc-url <RPC_URL>

# ERC-1155 balance
cast call <NFT> "balanceOf(address,uint256)(uint256)" <COMPROMISED> <TOKEN_ID> --rpc-url <RPC_URL>
```

For NFT discovery (finding which token IDs a wallet holds), read `references/nft-discovery.md`.

If the attacker has a sweep bot actively draining assets, prioritize the highest-value items and move fast.

---

### Phase 2 — Generate Operator Wallet (encrypted keystore)

Generate the operator wallet straight into an encrypted Foundry keystore. The raw private key is never printed — only the address — so the agent never handles the key directly.

```bash
# 1. Generate a strong random keystore password and save it (readable only by you)
openssl rand -hex 32 > operator-password.txt
chmod 600 operator-password.txt

# 2. Create the operator wallet as an encrypted keystore. Prints ONLY the address.
#    The keystore directory must exist first.
mkdir -p ./operator-keystore
CAST_PASSWORD="$(cat operator-password.txt)" \
  cast wallet new ./operator-keystore operator
```

This writes `./operator-keystore/operator` (an encrypted Web3 Secret Storage JSON keystore) and prints the operator address. `recover.ts` decrypts the keystore in-memory at runtime using `operator-password.txt` — the key is never written in plaintext anywhere.

Passing the password via `CAST_PASSWORD` (rather than `--unsafe-password`) keeps it out of your shell history and the process list. Keep `operator-keystore/` and `operator-password.txt` together — both are needed to broadcast.

Surface the address to the user clearly — they need to send gas to it.

---

### Phase 3 — Estimate Gas and Request Funding

For each chain, estimate gas needed:

- **Base EIP-7702 tx overhead**: ~50,000 gas
- **ERC-20 transfer**: ~50,000 gas per token
- **ERC-721 transferFrom**: ~60,000 gas per NFT
- **ERC-1155 safeTransferFrom**: ~70,000 gas per token ID
- **Native sweep** (if compromised wallet has ETH): free — happens automatically at the end

Get current gas price:
```bash
cast gas-price --rpc-url <RPC_URL>
```

Multiply total gas by gas price, add **30% buffer**, and present:

> "Please send at least **X ETH** to operator wallet `0x...` on **[Chain]**. Let me know once it confirms."

For multiple chains, the user must fund the operator on each chain separately (the operator address is the same everywhere since it's a plain EOA).

---

### Phase 4 — User Signs EIP-7702 Authorization

The delegate contract address is **the same on all supported chains**:
```
0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892
```

Give the user the bundled `scripts/sign-auth.sh` to run in their own terminal. It uses the
curated read RPC for each chain (no RPC for them to choose or get wrong) and prompts for the
key interactively, so the key never appears in their shell history or the process list:

```bash
./scripts/sign-auth.sh <CHAIN_ID> [<CHAIN_ID> ...]
# e.g. ./scripts/sign-auth.sh 1        (Ethereum)
#      ./scripts/sign-auth.sh 1 56 100 (Ethereum + BSC + Gnosis)
```

It prompts once for the key (input masked as `*` so the user sees their paste registered),
then prints a clearly-delineated handoff banner and a labeled authorization signature per
chain. The banner tells the user the output is safe to share and is **not** their private
key — so they don't mistake it for a secret. The user pastes the signature(s) back. **Do not
ask the user for the private key, and do not give them a raw `cast` command with a `--rpc-url`
they fill in** — that reintroduces the untrusted-RPC attack surface this script removes.

The output for each chain is a single hex string — the RLP-encoded authorization — e.g.:
```
0xf85c0194681bcbc1fbc1c8a2f1f5b4a43e6d38c5ca22089282119780a08c7fe49...
```

Ask the user to paste this hex string back. **This is cryptographically safe to share** — it only authorizes the specific delegate contract and is bound to the current nonce; it cannot be reused. It decodes to `[chainId, address, nonce, yParity, r, s]`, and `recover.ts` parses it automatically.

For multiple chains, pass several chain ids in one invocation (`./scripts/sign-auth.sh 1 56`); it signs for each and labels the output.

**Timing note**: The authorization is bound to the compromised EOA's current account nonce. If the attacker sends any transaction from that account before you broadcast, the authorization goes stale and must be re-signed. On chains with public mempools (Ethereum, BSC, Gnosis), broadcast immediately via the private execution RPC — see Supported Chains. Have the user re-run `sign-auth` right before you broadcast.

---

### Phase 5 — Write and Run the Recovery Script

Read `references/recover-template.ts` for the full annotated script template.
For NFT encoding (ERC-721 / ERC-1155), read `references/nft-discovery.md`.

Create `recover.ts` from the template, filling in:

| Variable | Value |
|----------|-------|
| `KEYSTORE_PATH` | Keystore from Phase 2 (`./operator-keystore/operator`) |
| `PASSWORD_FILE` | Password file from Phase 2 (`./operator-password.txt`) |
| `COMPROMISED_ADDRESS` | From Phase 1 |
| `SAFE_ADDRESS` | From Phase 1 |
| `CHAIN_ID` | Target chain (must be in the curated registry) |
| `AUTHORIZATION_HEX` | Hex string from Phase 4 |
| `CALLS` | Built from assets (see Asset Call Encoding below) |

`RPC_URL` and `EXECUTION_RPC_URL` are **not** filled in — they are derived from `CHAIN_ID`
via the embedded registry. Leave `ACK_UNSAFE_MEMPOOL = false` unless recovering on an
`unsafe` chain after warning the user (see Enforcement above).

Install and run (pin viem to a version with stable EIP-7702 support — the template is verified against `viem@^2.44`):
```bash
npm install viem@^2.44
npx tsx recover.ts
```

Or without tsx:
```bash
npm install viem@^2.44 typescript ts-node
npx ts-node --esm recover.ts
```

The script will print the transaction hash and wait for the receipt.

For multiple chains, run the script once per chain with its own authorization and calls.

---

### Phase 6 — Confirm and Clean Up

1. Verify the transaction on a block explorer using the printed hash.
2. Check the safe wallet received all expected assets.
3. The operator wallet's remaining ETH can be sent back to the user.

**If the transaction reverted**, read the error carefully:

| Error | Cause | Fix |
|-------|-------|-----|
| `InvalidNonce(signer, expected, provided)` | Attacker sent a tx before you | Re-run Phase 4 for a fresh authorization |
| `CallFailed(i, to, ...)` | Asset at call index `i` no longer exists | Remove that call from `CALLS` and retry |
| `IntentExpired` | deadline was set too low | Use `deadline = 0n` (no expiry) |
| `InvalidSignature` | Operator address mismatch | Double-check `authorizer` matches the operator wallet address |

---

## Supported Chains

Contract address on all chains: `0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892`

This table is the canonical human copy of the registry embedded in `recover.ts`
(`CHAIN_RPCS`) and `scripts/sign-auth.sh`. **Keep all three in sync.** Every read RPC below
was verified to host the delegate (`cast code` returns the same runtime bytecode).

| Chain | ID | Class | Read RPC | Execution RPC |
|-------|----|-------|----------|---------------|
| Ethereum | 1 | `relay` | `https://ethereum-rpc.publicnode.com` | `https://rpc.flashbots.net/fast` |
| BSC | 56 | `relay` | `https://bsc-rpc.publicnode.com` | `https://bsc.blinklabs.xyz/v1/` |
| Gnosis | 100 | `relay` | `https://gnosis-rpc.publicnode.com` | `https://erpc.gnosis.shutter.network` |
| Optimism | 10 | `sequencer` | `https://optimism-rpc.publicnode.com` | = read |
| Unichain | 130 | `sequencer` | `https://unichain-rpc.publicnode.com` | = read |
| Monad | 143 | `sequencer` | `https://rpc.monad.xyz` | = read |
| World | 480 | `sequencer` | `https://worldchain-mainnet.g.alchemy.com/public` | = read |
| Soneium | 1868 | `sequencer` | `https://rpc.soneium.org` | = read |
| Ronin | 2020 | `sequencer` | `https://api.roninchain.com/rpc` | = read |
| Mantle | 5000 | `sequencer` | `https://mantle-rpc.publicnode.com` | = read |
| Base | 8453 | `sequencer` | `https://base-rpc.publicnode.com` | = read |
| Arbitrum | 42161 | `sequencer` | `https://arbitrum-one-rpc.publicnode.com` | = read |
| Avalanche | 43114 | `sequencer` | `https://avalanche-c-chain-rpc.publicnode.com` | = read |
| Ink | 57073 | `sequencer` | `https://rpc-gel.inkonchain.com` | = read |
| Blast | 81457 | `sequencer` | `https://rpc.blast.io` | = read |
| Katana | 747474 | `sequencer` | `https://rpc.katana.network` | = read |
| Zora | 7777777 | `sequencer` | `https://rpc.zora.energy` | = read |
| Celo | 42220 | ⚠️ `unsafe` | `https://celo-rpc.publicnode.com` | = read (front-runnable — see Enforcement) |

> The registry in `recover.ts` (`CHAIN_RPCS`) and `scripts/sign-auth.sh` is the source of
> truth for supported chains. Before adding any chain, verify the delegate has code on it
> (`cast code 0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892 --rpc-url <RPC>` returns non-empty)
> and classify its mempool correctly (`relay` / `sequencer` / `unsafe`).

For `relay` chains, the registry's execution RPC (a private relay) is used for broadcast and
the read RPC for all queries. For `sequencer` chains, broadcast and reads share the RPC. For
the `unsafe` chain (Celo), follow the Enforcement rules above — warn the user and only proceed
with explicit confirmation.

---

## Asset Call Encoding

Native ETH is swept automatically at the end of `executeBatchRecovery` — no explicit call needed for native balances. Everything else needs a `Call` entry:

```typescript
// ERC-20: transfer all tokens
{
  to: "0xTOKEN_ADDRESS",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]),
    functionName: "transfer",
    args: [SAFE_ADDRESS, TOKEN_AMOUNT],
  })
}

// ERC-721: transfer one NFT
{
  to: "0xNFT_ADDRESS",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi(["function transferFrom(address from, address to, uint256 tokenId)"]),
    functionName: "transferFrom",
    args: [COMPROMISED_ADDRESS, SAFE_ADDRESS, TOKEN_ID],  // BigInt
  })
}

// ERC-1155: transfer tokens
{
  to: "0xNFT_ADDRESS",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi(["function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)"]),
    functionName: "safeTransferFrom",
    args: [COMPROMISED_ADDRESS, SAFE_ADDRESS, TOKEN_ID, AMOUNT, "0x"],
  })
}
```

Quick calldata encoding with cast (useful for verifying):
```bash
cast calldata "transfer(address,uint256)" <SAFE> <AMOUNT>
cast calldata "transferFrom(address,address,uint256)" <COMPROMISED> <SAFE> <TOKEN_ID>
```

See `references/nft-discovery.md` for finding token IDs and batch ERC-1155 encoding.

---

## EIP-712 Domain — Critical Detail

The `verifyingContract` in the EIP-712 domain is the **compromised EOA address**, not the delegate contract. Under EIP-7702, the delegate code executes at the EOA's address, so `address(this)` inside the contract resolves to the EOA. This is unusual and easy to get wrong.

```typescript
domain: {
  name: "UniversalRecoveryDelegate",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: COMPROMISED_ADDRESS,  // ← EOA address, NOT 0x681BcBC1...
}
```

The `recover.ts` template handles this correctly — just make sure the address substitution is right if manually constructing typed data.
