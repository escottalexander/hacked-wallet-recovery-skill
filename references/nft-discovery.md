# NFT Discovery and Encoding

ERC-721 and ERC-1155 tokens require the specific token ID(s) the compromised wallet holds. This file documents how to find them and how to build the correct CALLS entries.

## Finding ERC-721 Token IDs

### Via transfer events (most reliable)

```bash
# Get all Transfer events where 'to' = compromised wallet (recent 10k blocks)
cast logs \
  --from-block latest \
  --to-block latest \
  --address <NFT_CONTRACT> \
  "Transfer(address indexed from, address indexed to, uint256 indexed tokenId)" \
  --rpc-url <RPC_URL> \
  | grep -A3 "topics"
```

### Verify current ownership

```bash
# Confirm the compromised wallet still owns a specific token
cast call <NFT_CONTRACT> \
  "ownerOf(uint256)(address)" \
  <TOKEN_ID> \
  --rpc-url <RPC_URL>
```

### Check if wallet is approved (attacker might have set approval)

```bash
# Who is approved to transfer this token?
cast call <NFT_CONTRACT> \
  "getApproved(uint256)(address)" \
  <TOKEN_ID> \
  --rpc-url <RPC_URL>

# Is the attacker an operator for all tokens?
cast call <NFT_CONTRACT> \
  "isApprovedForAll(address,address)(bool)" \
  <COMPROMISED> <ATTACKER> \
  --rpc-url <RPC_URL>
```

If the attacker already has `setApprovalForAll` → they may drain NFTs independently. The recovery transaction must execute **before** they do. Move fast.

## Encoding ERC-721 CALLS Entry

```typescript
// ERC-721: transferFrom (preferred over safeTransferFrom — avoids IERC721Receiver check)
{
  to: "0xNFT_CONTRACT",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi(["function transferFrom(address from, address to, uint256 tokenId)"]),
    functionName: "transferFrom",
    args: [COMPROMISED_ADDRESS, SAFE_ADDRESS, TOKEN_ID_AS_BIGINT],
  }),
}
```

**Use `transferFrom` not `safeTransferFrom`** — `safeTransferFrom` calls `onERC721Received` on the recipient and will revert if the safe wallet is a smart contract that doesn't implement it (e.g., some Safes).

## Finding ERC-1155 Token IDs

ERC-1155 contracts don't have a standard enumeration interface. Best approaches:

### Via TransferSingle/TransferBatch events

```bash
# TransferSingle: single token type transferred to compromised wallet
cast logs \
  --address <ERC1155_CONTRACT> \
  "TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value)" \
  --rpc-url <RPC_URL>

# TransferBatch: multiple token types
cast logs \
  --address <ERC1155_CONTRACT> \
  "TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values)" \
  --rpc-url <RPC_URL>
```

### Verify current balance for a known token ID

```bash
cast call <ERC1155_CONTRACT> \
  "balanceOf(address,uint256)(uint256)" \
  <COMPROMISED> <TOKEN_ID> \
  --rpc-url <RPC_URL>
```

## Encoding ERC-1155 CALLS Entry

```typescript
// ERC-1155: single token type
{
  to: "0xERC1155_CONTRACT",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi([
      "function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)"
    ]),
    functionName: "safeTransferFrom",
    args: [COMPROMISED_ADDRESS, SAFE_ADDRESS, TOKEN_ID_AS_BIGINT, AMOUNT_AS_BIGINT, "0x"],
  }),
}

// ERC-1155: multiple token types in one call (gas efficient)
{
  to: "0xERC1155_CONTRACT",
  value: 0n,
  data: encodeFunctionData({
    abi: parseAbi([
      "function safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)"
    ]),
    functionName: "safeBatchTransferFrom",
    args: [
      COMPROMISED_ADDRESS, SAFE_ADDRESS,
      [TOKEN_ID_1, TOKEN_ID_2],   // BigInt[]
      [AMOUNT_1, AMOUNT_2],        // BigInt[]
      "0x"
    ],
  }),
}
```

**Prefer `safeBatchTransferFrom`** when recovering multiple token IDs from the same ERC-1155 contract — one call instead of N.

## Gas Estimates for CALLS Ordering

Add items to CALLS in any order — `executeBatchRecovery` runs them sequentially and stops on the first failure (use Phase 4 error table to debug). Rough per-call gas costs:

| Asset type | Gas |
|------------|-----|
| ERC-20 transfer | ~45,000 |
| ERC-721 transferFrom | ~55,000 |
| ERC-1155 safeTransferFrom | ~65,000 |
| ERC-1155 safeBatchTransferFrom | ~65,000 + ~15,000/extra ID |
| EIP-7702 + delegate overhead | ~50,000 fixed |

The recovery script adds a 20% gas buffer automatically.

## Known NFT Collections (Ethereum mainnet)

| Collection | Contract |
|------------|---------|
| CryptoPunks (wrapped) | `0xb7F7F6C52F2e2fdb1963Eab30438024864c313F6` |
| Bored Ape Yacht Club | `0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D` |
| Mutant Ape Yacht Club | `0x60E4d786628Fea6478F785A6d7e704777c86a7c6` |
| Azuki | `0xED5AF388653567Af2F388E6224dC7C4b3241C544` |
| CloneX | `0x49cF6f5d44E70224e2E23fDcdd2C053F30aDA28B` |
| Doodles | `0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e` |
| Pudgy Penguins | `0xBd3531dA5CF5857e7CfAA92426877b022e612cf8` |
| Art Blocks | `0xa7d8d9ef8D8Ce8992Df33D8b8CF4Aebabd5bD270` |
| Nouns | `0x9C8fF314C9Bc7F6e59A9d9225Fb22946427eDC03` |
