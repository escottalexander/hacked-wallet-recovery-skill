// Build a concrete recover.ts from the verbatim skill template by substituting CONFIG.
import { readFileSync, writeFileSync } from "node:fs";

const t = readFileSync("./recover-template.ts", "utf8");
const E = process.env;

let out = t
  .replace(/const COMPROMISED_ADDRESS: Address = "[^"]*";/, `const COMPROMISED_ADDRESS: Address = "${E.COMPROMISED}";`)
  .replace(/const SAFE_ADDRESS: Address = "[^"]*";/, `const SAFE_ADDRESS: Address = "${E.SAFE}";`)
  // RPC_URL/EXECUTION_RPC_URL are no longer editable fields — they are derived from
  // the curated CHAIN_RPCS registry by CHAIN_ID. Point the chain-1 entry (read + exec)
  // at the local fork. This is a TEST-ONLY build-time patch; production recover.ts has
  // no runtime RPC override.
  .replace(
    /(\n\s*1:\s*\{[^\n]*?readRpc:\s*)"[^"]*"([^\n]*?execRpc:\s*)"[^"]*"/,
    `$1"${E.FORK_RPC}"$2"${E.FORK_RPC}"`,
  )
  .replace(/const AUTHORIZATION_HEX: Hex = "[^"]*";/, `const AUTHORIZATION_HEX: Hex = "${E.AUTH_HEX}";`)
  .replace(
    /const CALLS:[\s\S]*?\n\];/,
    `const CALLS: { to: Address; value: bigint; data: Hex }[] = [
  {
    to: "${E.DAI}",
    value: 0n,
    data: encodeFunctionData({
      abi: parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]),
      functionName: "transfer",
      args: [SAFE_ADDRESS, ${E.DAI_AMOUNT}n],
    }),
  },
];`
  );

// sanity: every placeholder must be gone, and the chain-1 registry entry must have
// been repointed at the fork (the default read + exec URLs must no longer be present).
for (const bad of ['"0x..."', "COMPROMISED = ", "flashbots", "ethereum-rpc.publicnode.com"]) {
  if (out.includes(bad)) { console.error("UNREPLACED placeholder:", bad); process.exit(1); }
}
if (!out.includes(E.FORK_RPC)) { console.error("chain-1 registry not repointed to FORK_RPC"); process.exit(1); }
writeFileSync("./recover.ts", out);
console.log("recover.ts written");
