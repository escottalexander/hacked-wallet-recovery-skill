/**
 * Hacked Wallet Recovery Script
 *
 * Dependency: npm install viem
 * Run:        npx tsx recover.ts
 *             (or: npx ts-node --esm recover.ts)
 *
 * Fill in the CONFIG section below, then run.
 * The operator key lives in an encrypted Foundry keystore — it is never written
 * in plaintext here. The script decrypts it in-memory at runtime using the
 * password file. The compromised private key is NEVER in this file.
 */

import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  encodeAbiParameters,
  http,
  keccak256,
  parseAbi,
  parseAbiParameters,
  stringToHex,
  toHex,
  hexToBigInt,
  fromRlp,
  padHex,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { defineChain } from "viem";
import { scryptSync, pbkdf2Sync, createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";

// ═══════════════════════════════════════════════════════
//  CONFIG — fill these in
// ═══════════════════════════════════════════════════════

// Operator wallet — an encrypted Foundry keystore generated in Phase 2.
// The raw key never appears here; it is decrypted in-memory at runtime.
const KEYSTORE_PATH = "./operator-keystore/operator"; // Created by: cast wallet new ./operator-keystore operator
const PASSWORD_FILE = "./operator-password.txt";       // The keystore password (one line)

const COMPROMISED_ADDRESS: Address = "0x...";  // Public address of hacked wallet
const SAFE_ADDRESS: Address = "0x...";         // Destination for recovered assets

const CHAIN_ID = 1;                                       // Target chain ID (must be in the curated registry below)

// Mempool-safety acknowledgement. LEAVE THIS false. Only set it true for a chain
// whose registry `mempool` class is "unsafe" (e.g. Celo), and ONLY after you have
// explicitly warned the user that an attacker watching the mempool can front-run
// with a nonce-bumping tx and invalidate the recovery. See SKILL.md "Why private mempools".
const ACK_UNSAFE_MEMPOOL = false;

// RPC_URL (reads) and EXECUTION_RPC_URL (broadcast) are NOT set here — they are
// derived from CHAIN_ID via the curated registry below. There is intentionally no
// way to substitute an arbitrary RPC: the registry is the enforced trust boundary.

// Paste the hex string output by (Phase 4):
//   cast wallet sign-auth 0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892 \
//     --private-key <COMPROMISED_KEY> --rpc-url <RPC_URL>
// It is the RLP-encoded EIP-7702 authorization: [chainId, address, nonce, yParity, r, s].
const AUTHORIZATION_HEX: Hex = "0x...";

// Calls to execute — one entry per token/NFT. Native ETH is swept automatically.
// See SKILL.md "Asset Call Encoding" for how to build each entry.
const CALLS: { to: Address; value: bigint; data: Hex }[] = [
  // Example ERC-20:
  // {
  //   to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",   // USDC on Ethereum
  //   value: 0n,
  //   data: encodeFunctionData({
  //     abi: parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]),
  //     functionName: "transfer",
  //     args: [SAFE_ADDRESS, 1_000_000n],  // 1 USDC (6 decimals)
  //   }),
  // },
];

// ═══════════════════════════════════════════════════════
//  INTERNALS — no need to edit below this line
// ═══════════════════════════════════════════════════════

const DELEGATE_ADDRESS: Address = "0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892";

// ── Curated chain registry — the enforced trust boundary ───────────────────────
// Read + execution RPCs and mempool classification for every chain the delegate is
// deployed on. The agent/user may NOT substitute an arbitrary RPC; recovery is
// restricted to these vetted entries. All read RPCs verified to host the delegate
// (cast code <delegate> returns the same 13490-byte runtime on every chain).
//
// mempool classes:
//   "relay"     — public, outsider-queryable mempool; execRpc MUST be a private
//                 relay so the tx is hidden until inclusion (prevents the attacker
//                 from seeing it and front-running a nonce-bumping tx).
//   "sequencer" — no outsider-queryable mempool (centralized sequencer only sees
//                 pending txs); safe via any RPC, so execRpc = readRpc.
//   "unsafe"    — attacker may observe the mempool and no relay is available;
//                 broadcasting here can be front-run. Gated behind ACK_UNSAFE_MEMPOOL.
//
// Keep in sync with scripts/sign-auth.sh and SKILL.md "Supported Chains".
type Mempool = "relay" | "sequencer" | "unsafe";
const CHAIN_RPCS: Record<number, { name: string; readRpc: string; execRpc: string; mempool: Mempool }> = {
  1:       { name: "Ethereum",  readRpc: "https://ethereum-rpc.publicnode.com",             execRpc: "https://rpc.flashbots.net/fast",                 mempool: "relay" },
  10:      { name: "Optimism",  readRpc: "https://optimism-rpc.publicnode.com",             execRpc: "https://optimism-rpc.publicnode.com",            mempool: "sequencer" },
  56:      { name: "BSC",       readRpc: "https://bsc-rpc.publicnode.com",                  execRpc: "https://bsc.blinklabs.xyz/v1/",                  mempool: "relay" },
  100:     { name: "Gnosis",    readRpc: "https://gnosis-rpc.publicnode.com",               execRpc: "https://erpc.gnosis.shutter.network",            mempool: "relay" },
  130:     { name: "Unichain",  readRpc: "https://unichain-rpc.publicnode.com",             execRpc: "https://unichain-rpc.publicnode.com",            mempool: "sequencer" },
  143:     { name: "Monad",     readRpc: "https://rpc.monad.xyz",                           execRpc: "https://rpc.monad.xyz",                          mempool: "sequencer" },
  480:     { name: "World",     readRpc: "https://worldchain-mainnet.g.alchemy.com/public", execRpc: "https://worldchain-mainnet.g.alchemy.com/public", mempool: "sequencer" },
  1868:    { name: "Soneium",   readRpc: "https://rpc.soneium.org",                         execRpc: "https://rpc.soneium.org",                        mempool: "sequencer" },
  2020:    { name: "Ronin",     readRpc: "https://api.roninchain.com/rpc",                  execRpc: "https://api.roninchain.com/rpc",                 mempool: "sequencer" },
  5000:    { name: "Mantle",    readRpc: "https://mantle-rpc.publicnode.com",               execRpc: "https://mantle-rpc.publicnode.com",              mempool: "sequencer" },
  8453:    { name: "Base",      readRpc: "https://base-rpc.publicnode.com",                 execRpc: "https://base-rpc.publicnode.com",                mempool: "sequencer" },
  42161:   { name: "Arbitrum",  readRpc: "https://arbitrum-one-rpc.publicnode.com",         execRpc: "https://arbitrum-one-rpc.publicnode.com",        mempool: "sequencer" },
  42220:   { name: "Celo",      readRpc: "https://celo-rpc.publicnode.com",                 execRpc: "https://celo-rpc.publicnode.com",                mempool: "unsafe" },
  43114:   { name: "Avalanche", readRpc: "https://avalanche-c-chain-rpc.publicnode.com",    execRpc: "https://avalanche-c-chain-rpc.publicnode.com",   mempool: "sequencer" },
  57073:   { name: "Ink",       readRpc: "https://rpc-gel.inkonchain.com",                  execRpc: "https://rpc-gel.inkonchain.com",                 mempool: "sequencer" },
  81457:   { name: "Blast",     readRpc: "https://rpc.blast.io",                            execRpc: "https://rpc.blast.io",                           mempool: "sequencer" },
  747474:  { name: "Katana",    readRpc: "https://rpc.katana.network",                      execRpc: "https://rpc.katana.network",                     mempool: "sequencer" },
  7777777: { name: "Zora",      readRpc: "https://rpc.zora.energy",                         execRpc: "https://rpc.zora.energy",                        mempool: "sequencer" },
};

const _chain = CHAIN_RPCS[CHAIN_ID];
if (!_chain) {
  throw new Error(
    `Chain ${CHAIN_ID} is not in the curated registry — refusing to broadcast through an untrusted RPC.\n` +
    `Supported: ${Object.keys(CHAIN_RPCS).join(", ")}.\n` +
    `Vet a new chain first (cast code ${DELEGATE_ADDRESS} --rpc-url <RPC> must return code), then add it deliberately.`
  );
}
if (_chain.mempool === "unsafe" && !ACK_UNSAFE_MEMPOOL) {
  throw new Error(
    `Chain ${CHAIN_ID} (${_chain.name}) has an observable/unknown mempool. An attacker watching it can ` +
    `front-run with a nonce-bumping tx and invalidate this recovery. Set ACK_UNSAFE_MEMPOOL = true ` +
    `ONLY after explicitly warning the user (see SKILL.md "Why private mempools").`
  );
}
const RPC_URL = _chain.readRpc;
const EXECUTION_RPC_URL = _chain.execRpc;

// Decode the RLP authorization tuple from cast: [chainId, address, nonce, yParity, r, s].
// viem expects `contractAddress` for the delegate target; provide it (plus `address`
// for compatibility). r/s are left-padded to 32 bytes since RLP strips leading zeros.
const _authParts = fromRlp(AUTHORIZATION_HEX, "hex") as Hex[];
const _h2b = (h?: Hex) => (!h || h === "0x" ? 0n : hexToBigInt(h));
const AUTHORIZATION = {
  chainId: CHAIN_ID,
  address: _authParts[1] as Address,
  contractAddress: _authParts[1] as Address,
  nonce: _h2b(_authParts[2]),
  yParity: Number(_h2b(_authParts[3])) as 0 | 1,
  r: padHex(_authParts[4], { size: 32 }),
  s: padHex(_authParts[5], { size: 32 }),
};

// Sanity-check: the authorization must target the right delegate and chain.
if (AUTHORIZATION.address.toLowerCase() !== DELEGATE_ADDRESS.toLowerCase()) {
  throw new Error(
    `Authorization targets wrong delegate: ${AUTHORIZATION.address}\n` +
    `Expected: ${DELEGATE_ADDRESS}\n` +
    `Re-run: cast wallet sign-auth ${DELEGATE_ADDRESS} --private-key <KEY> --rpc-url <RPC_URL>`
  );
}
if (Number(_h2b(_authParts[0])) !== CHAIN_ID) {
  throw new Error(`Authorization chainId ${Number(_h2b(_authParts[0]))} does not match CHAIN_ID ${CHAIN_ID}.`);
}

const DELEGATE_ABI = parseAbi([
  "function executeBatchRecovery(address recoveryAddress, (address to, uint256 value, bytes data)[] calls, address authorizer, uint256 nonce, uint256 deadline, bytes signature) payable",
  "function nonces(address authorizer) view returns (uint256)",
]);

// EIP-712 type hash for a single Call struct
const CALL_TYPEHASH = keccak256(stringToHex("Call(address to,uint256 value,bytes data)"));

function hashCalls(calls: { to: Address; value: bigint; data: Hex }[]): Hex {
  const callHashes = calls.map((c) =>
    keccak256(
      encodeAbiParameters(parseAbiParameters("bytes32,address,uint256,bytes32"), [
        CALL_TYPEHASH,
        c.to,
        c.value,
        keccak256(c.data),
      ])
    )
  );
  return keccak256(encodeAbiParameters(parseAbiParameters("bytes32[]"), [callHashes]));
}

// Unstructured storage slot for the delegate's nonce mapping.
// Matches: bytes32(uint256(keccak256("hwr.universalRecoveryDelegate.storage.v1")) - 1)
const DELEGATE_STORAGE_SLOT = toHex(
  hexToBigInt(keccak256(stringToHex("hwr.universalRecoveryDelegate.storage.v1"))) - 1n,
  { size: 32 }
) as Hex;

// Decrypt a Web3 Secret Storage v3 keystore (the format Foundry's `cast wallet new`
// writes) using only Node built-ins + viem's keccak256 — no extra dependency.
// Supports scrypt (cast's default) and pbkdf2. Returns the 0x-prefixed private key.
function loadOperatorKey(keystorePath: string, passwordFile: string): Hex {
  const ks = JSON.parse(readFileSync(keystorePath, "utf8"));
  // Match `$(cat file)` semantics used to set CAST_PASSWORD: trailing newline trimmed.
  const password = readFileSync(passwordFile, "utf8").trim();
  const c = ks.crypto ?? ks.Crypto;
  const kp = c.kdfparams;
  const pw = Buffer.from(password, "utf8");

  let dk: Buffer;
  if (c.kdf === "scrypt") {
    dk = scryptSync(pw, Buffer.from(kp.salt, "hex"), kp.dklen, {
      N: kp.n, r: kp.r, p: kp.p, maxmem: 512 * 1024 * 1024,
    });
  } else if (c.kdf === "pbkdf2") {
    dk = pbkdf2Sync(pw, Buffer.from(kp.salt, "hex"), kp.c, kp.dklen, "sha256");
  } else {
    throw new Error(`Unsupported keystore kdf: ${c.kdf}`);
  }

  const cipherBuf = Buffer.from(c.ciphertext, "hex");
  // MAC = keccak256(derivedKey[16:32] ++ ciphertext)
  const mac = keccak256(new Uint8Array([...dk.subarray(16, 32), ...cipherBuf])).slice(2);
  if (mac !== String(c.mac).toLowerCase()) {
    throw new Error("Keystore decryption failed: wrong password (MAC mismatch)");
  }

  const decipher = createDecipheriv("aes-128-ctr", dk.subarray(0, 16), Buffer.from(c.cipherparams.iv, "hex"));
  const pk = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);
  return ("0x" + pk.toString("hex")) as Hex;
}

async function main() {
  const operatorPrivateKey = loadOperatorKey(KEYSTORE_PATH, PASSWORD_FILE);
  const operatorAccount = privateKeyToAccount(operatorPrivateKey);
  console.log("Operator address:", operatorAccount.address);

  const chain = defineChain({ id: CHAIN_ID, name: `chain-${CHAIN_ID}`, nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC_URL] } } });
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });

  // Read the operator's current intent nonce from the compromised EOA's storage.
  // Nonce is stored in the delegate's unstructured mapping: keccak256(abi.encode(operator, STORAGE_SLOT))
  const nonceSlot = keccak256(
    encodeAbiParameters(parseAbiParameters("address,bytes32"), [
      operatorAccount.address,
      DELEGATE_STORAGE_SLOT,
    ])
  );
  const nonceRaw = await publicClient.getStorageAt({ address: COMPROMISED_ADDRESS, slot: nonceSlot });
  const intentNonce = hexToBigInt(nonceRaw ?? "0x0");
  console.log("Intent nonce:", intentNonce);

  // Check operator balance
  const operatorBalance = await publicClient.getBalance({ address: operatorAccount.address });
  console.log("Operator balance:", operatorBalance, "wei");
  if (operatorBalance === 0n) {
    throw new Error("Operator wallet has no ETH. Fund it first.");
  }

  // Build the EIP-712 recovery intent and sign it with the operator key.
  // verifyingContract is the COMPROMISED EOA (under 7702, address(this) = EOA)
  const callsHash = hashCalls(CALLS);
  const deadline = 0n; // 0 = no expiry

  const signature = await operatorAccount.signTypedData({
    domain: {
      name: "UniversalRecoveryDelegate",
      version: "1",
      chainId: CHAIN_ID,
      verifyingContract: COMPROMISED_ADDRESS,
    },
    types: {
      RecoveryIntent: [
        { name: "recoveryAddress", type: "address" },
        { name: "callsHash", type: "bytes32" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    },
    primaryType: "RecoveryIntent",
    message: {
      recoveryAddress: SAFE_ADDRESS,
      callsHash,
      nonce: intentNonce,
      deadline,
    },
  });
  console.log("Recovery intent signed.");

  // Encode the executeBatchRecovery calldata.
  const recoverCalldata = encodeFunctionData({
    abi: DELEGATE_ABI,
    functionName: "executeBatchRecovery",
    args: [
      SAFE_ADDRESS,
      CALLS,
      operatorAccount.address, // authorizer = operator (it signed the intent above)
      intentNonce,
      deadline,
      signature,
    ],
  });

  // Estimate gas for the EIP-7702 call. Many public RPCs can't estimate a type-4
  // tx (or under-estimate it), so pad generously and fall back if estimation fails.
  let gas: bigint;
  try {
    const est = await publicClient.estimateGas({
      to: COMPROMISED_ADDRESS,
      data: recoverCalldata,
      account: operatorAccount.address,
      type: "eip7702",
      authorizationList: [AUTHORIZATION],
    } as any);
    gas = (est * 12n) / 10n + 50_000n; // +20% +fixed buffer
  } catch {
    gas = 300_000n + BigInt(CALLS.length) * 70_000n; // conservative fallback
  }

  const fees = await publicClient.estimateFeesPerGas().catch(() => null);

  // Broadcast the EIP-7702 transaction via the execution RPC.
  const walletClient = createWalletClient({
    account: operatorAccount,
    chain,
    transport: http(EXECUTION_RPC_URL),
  });

  console.log("Broadcasting transaction...");
  const hash = await walletClient.sendTransaction({
    to: COMPROMISED_ADDRESS,
    data: recoverCalldata,
    type: "eip7702",
    authorizationList: [AUTHORIZATION],
    gas,
    maxFeePerGas: fees?.maxFeePerGas,
    maxPriorityFeePerGas: fees?.maxPriorityFeePerGas,
  } as any); // `as any`: viem's 7702 tx typing varies across 2.x minor versions

  console.log("Transaction hash:", hash);
  console.log(`Explorer: https://etherscan.io/tx/${hash}`);

  console.log("Waiting for receipt...");
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status === "success") {
    console.log("✓ Recovery succeeded!");
  } else {
    console.error("✗ Transaction reverted. Check the hash on a block explorer for revert reason.");
  }
}

main().catch((err) => {
  console.error("Error:", err.message ?? err);
  process.exit(1);
});
