#!/usr/bin/env node
/**
 * check-assets.js — audit ERC-20/721 holdings of a compromised wallet
 *
 * Usage:
 *   node check-assets.js <address> <rpc-url> [token1,token2,...]
 *
 * Examples:
 *   # Native balance only
 *   node check-assets.js 0xAbCd... https://eth.llamarpc.com
 *
 *   # Native + specific ERC-20 tokens
 *   node check-assets.js 0xAbCd... https://eth.llamarpc.com \
 *     0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,0xdAC17F958D2ee523a2206206994597C13D831ec7
 *
 *   # Check all well-known tokens on Ethereum mainnet (chain 1)
 *   node check-assets.js 0xAbCd... https://eth.llamarpc.com mainnet
 *
 * Output: balance summary + copy-paste CALLS entries for recover.ts
 *
 * No npm dependencies — uses Node 18 built-in fetch.
 */

const [,, address, rpcUrl, tokensArg] = process.argv;

if (!address || !rpcUrl) {
  console.error('Usage: node check-assets.js <address> <rpc-url> [token1,token2,...|mainnet|base|arbitrum]');
  process.exit(1);
}

// Well-known tokens per network shorthand
const WELL_KNOWN = {
  mainnet: [
    { symbol: 'USDC',  address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', standard: 'erc20' },
    { symbol: 'USDT',  address: '0xdAC17F958D2ee523a2206206994597C13D831ec7', standard: 'erc20' },
    { symbol: 'WETH',  address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', standard: 'erc20' },
    { symbol: 'DAI',   address: '0x6B175474E89094C44Da98b954EedeAC495271d0F', standard: 'erc20' },
    { symbol: 'WBTC',  address: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599', standard: 'erc20' },
    { symbol: 'LINK',  address: '0x514910771AF9Ca656af840dff83E8264EcF986CA', standard: 'erc20' },
    { symbol: 'UNI',   address: '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984', standard: 'erc20' },
    { symbol: 'AAVE',  address: '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9', standard: 'erc20' },
    { symbol: 'CRV',   address: '0xD533a949740bb3306d119CC777fa900bA034cd52', standard: 'erc20' },
    { symbol: 'LDO',   address: '0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32', standard: 'erc20' },
    { symbol: 'stETH', address: '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84', standard: 'erc20' },
    { symbol: 'cbETH', address: '0xBe9895146f7AF43049ca1c1AE358B0541Ea49704', standard: 'erc20' },
    { symbol: 'rETH',  address: '0xae78736Cd615f374D3085123A210448E74Fc6393', standard: 'erc20' },
  ],
  base: [
    { symbol: 'USDC',  address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', standard: 'erc20' },
    { symbol: 'WETH',  address: '0x4200000000000000000000000000000000000006', standard: 'erc20' },
    { symbol: 'DAI',   address: '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb', standard: 'erc20' },
    { symbol: 'cbETH', address: '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22', standard: 'erc20' },
    { symbol: 'cbBTC', address: '0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf', standard: 'erc20' },
  ],
  arbitrum: [
    { symbol: 'USDC',  address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', standard: 'erc20' },
    { symbol: 'USDT',  address: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', standard: 'erc20' },
    { symbol: 'WETH',  address: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', standard: 'erc20' },
    { symbol: 'ARB',   address: '0x912CE59144191C1204E64559FE8253a0e49E6548', standard: 'erc20' },
    { symbol: 'DAI',   address: '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1', standard: 'erc20' },
    { symbol: 'WBTC',  address: '0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f', standard: 'erc20' },
  ],
  optimism: [
    { symbol: 'USDC',  address: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85', standard: 'erc20' },
    { symbol: 'USDT',  address: '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58', standard: 'erc20' },
    { symbol: 'WETH',  address: '0x4200000000000000000000000000000000000006', standard: 'erc20' },
    { symbol: 'OP',    address: '0x4200000000000000000000000000000000000042', standard: 'erc20' },
    { symbol: 'DAI',   address: '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1', standard: 'erc20' },
  ],
};

// ── RPC helpers ──────────────────────────────────────────────────────────────

let _reqId = 1;
async function rpc(method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: _reqId++, method, params }),
  });
  const { result, error } = await res.json();
  if (error) throw new Error(`RPC ${method}: ${error.message}`);
  return result;
}

// ABI-encode a single address parameter for eth_call (padded to 32 bytes)
function encodeAddress(addr) {
  return '0x' + addr.replace(/^0x/, '').toLowerCase().padStart(64, '0');
}

async function call(to, sig4byte, encoded) {
  return rpc('eth_call', [{ to, data: sig4byte + encoded.replace(/^0x/, '') }, 'latest']);
}

function hex2BigInt(h) { return h && h !== '0x' ? BigInt(h) : 0n; }
function formatUnits(val, dec) {
  const s = val.toString().padStart(dec + 1, '0');
  const int = s.slice(0, -dec) || '0';
  const frac = s.slice(-dec).replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int;
}

// ── Resolve token list ───────────────────────────────────────────────────────

let tokens = [];
if (!tokensArg) {
  // native only
} else if (WELL_KNOWN[tokensArg]) {
  tokens = WELL_KNOWN[tokensArg];
} else {
  tokens = tokensArg.split(',').map(a => ({ address: a.trim(), symbol: '?', standard: 'erc20' }));
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const wallet = address.toLowerCase();
  console.log(`\n🔍 Checking assets for ${wallet}\n`);

  // Native balance
  const nativeHex = await rpc('eth_getBalance', [wallet, 'latest']);
  const nativeWei = hex2BigInt(nativeHex);
  const nativeEth = formatUnits(nativeWei, 18);
  console.log(`Native:  ${nativeEth} ETH (${nativeWei} wei)`);
  if (nativeWei > 0n) {
    console.log(`  → Native is swept automatically — no CALLS entry needed\n`);
  }

  // ERC-20 tokens
  const nonZeroTokens = [];
  for (const token of tokens) {
    try {
      // balanceOf(address)
      const balHex = await call(token.address, '0x70a08231', encodeAddress(wallet));
      const balance = hex2BigInt(balHex);
      if (balance === 0n) continue;

      // symbol() — best effort
      let symbol = token.symbol;
      if (symbol === '?') {
        try {
          const symHex = await call(token.address, '0x95d89b41', '');
          // decode ABI-encoded string (offset + length + data)
          const data = symHex.replace(/^0x/, '');
          const len = parseInt(data.slice(64, 128), 16);
          symbol = Buffer.from(data.slice(128, 128 + len * 2), 'hex').toString('utf8');
        } catch { symbol = token.address.slice(0, 10) + '...'; }
      }

      // decimals() — best effort
      let decimals = 18;
      try {
        const decHex = await call(token.address, '0x313ce567', '');
        decimals = parseInt(decHex, 16) || 18;
      } catch {}

      const human = formatUnits(balance, decimals);
      console.log(`${symbol.padEnd(8)} ${human} (raw: ${balance})`);
      console.log(`  Contract: ${token.address}`);

      nonZeroTokens.push({ ...token, symbol, balance, decimals });
    } catch (e) {
      console.warn(`  [skip] ${token.address}: ${e.message}`);
    }
  }

  // ── Generate CALLS snippet ───────────────────────────────────────────────
  if (nonZeroTokens.length > 0) {
    console.log('\n─── Copy-paste this into recover.ts CALLS array ───────────────\n');
    for (const t of nonZeroTokens) {
      console.log(`  // ${t.symbol}: ${formatUnits(t.balance, t.decimals)} (${t.address})`);
      console.log(`  {`);
      console.log(`    to: "${t.address}",`);
      console.log(`    value: 0n,`);
      console.log(`    data: encodeFunctionData({`);
      console.log(`      abi: parseAbi(["function transfer(address,uint256)"]),`);
      console.log(`      functionName: "transfer",`);
      console.log(`      args: [SAFE_ADDRESS, ${t.balance}n],`);
      console.log(`    }),`);
      console.log(`  },`);
    }
    console.log('───────────────────────────────────────────────────────────────');
  }

  if (nonZeroTokens.length === 0 && nativeWei === 0n) {
    console.log('\nNo assets found. The wallet may already be drained.');
  }
}

main().catch(e => { console.error(e.message); process.exit(1); });
