#!/usr/bin/env bash
# End-to-end test of the hacked-wallet-recovery skill against REAL mainnet contract
# bytecode (the deployed UniversalRecoveryDelegate + DAI), exercising the exact flow
# a real recovery uses: cast wallet sign-auth -> keystore-based recover.ts -> EIP-7702
# type-4 broadcast -> on-chain execution -> assets land in the safe wallet.
#
# Why "graft" instead of `anvil --fork-url`: some sandboxes can't sustain anvil's
# fork-init request burst against public RPCs. This script instead pulls the real
# mainnet runtime bytecode for the two contracts we touch via single `cast code`
# calls and grafts them onto a local Prague chain with anvil_setCode — equivalent
# to forking just those contracts. If you have a permissive archive RPC, you can
# replace the "local anvil + graft" section with `anvil --fork-url <RPC> --hardfork
# prague --chain-id 1` and skip the setCode calls.
#
# Prereqshelp: foundry (anvil/cast), node >=18, network access for the two cast code
# calls, and `npm i viem@^2.44` in this directory.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=8546
FORK="http://127.0.0.1:$PORT"
PUB="${PUBLIC_RPC:-https://ethereum-rpc.publicnode.com}"
DELEGATE=0x681BcBC1fBc1c8A2f1F5b4A43e6D38c5CA220892
DAI=0x6B175474E89094C44Da98b954EedeAC495271d0F
export DAI

cd "$HERE"
[ -d node_modules/viem ] || npm install viem@^2.44 --silent
cp ../references/recover-template.ts ./recover-template.ts

echo "== fetch real mainnet bytecode (single calls) =="
cast code "$DELEGATE" --rpc-url "$PUB" > delegate.code
cast code "$DAI"      --rpc-url "$PUB" > dai.code

echo "== start local Prague anvil =="
pkill -f "anvil.*$PORT" 2>/dev/null || true; sleep 1
anvil --hardfork prague --chain-id 1 --port "$PORT" > anvil.log 2>&1 &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
until cast chain-id --rpc-url "$FORK" >/dev/null 2>&1; do sleep 1; done

echo "== graft delegate + DAI onto local chain =="
cast rpc anvil_setCode "$DELEGATE" "$(cat delegate.code)" --rpc-url "$FORK" >/dev/null
cast rpc anvil_setCode "$DAI"      "$(cat dai.code)"      --rpc-url "$FORK" >/dev/null

echo "== set up + fund accounts =="
COMPROMISED_KEY=0x1111111111111111111111111111111111111111111111111111111111111111
export COMPROMISED; COMPROMISED=$(cast wallet address --private-key "$COMPROMISED_KEY")
export SAFE;        SAFE=$(cast wallet address --private-key 0x2222222222222222222222222222222222222222222222222222222222222222)
openssl rand -hex 32 > operator-password.txt && chmod 600 operator-password.txt
rm -rf ./operator-keystore && mkdir -p ./operator-keystore
OPERATOR=$(CAST_PASSWORD="$(cat operator-password.txt)" cast wallet new ./operator-keystore operator 2>&1 | awk '/Address/{print $2}')
cast rpc anvil_setBalance "$COMPROMISED" 0x4563918244F40000 --rpc-url "$FORK" >/dev/null   # 5 ETH
cast rpc anvil_setBalance "$OPERATOR"    0x0DE0B6B3A7640000 --rpc-url "$FORK" >/dev/null   # 1 ETH
export DAI_AMOUNT=12345000000000000000000                                                  # 12345 DAI
cast rpc anvil_setStorageAt "$DAI" "$(cast index address "$COMPROMISED" 2)" "$(cast to-uint256 "$DAI_AMOUNT")" --rpc-url "$FORK" >/dev/null

echo "== run the real skill flow =="
export FORK_RPC="$FORK"
export AUTH_HEX; AUTH_HEX=$(cast wallet sign-auth "$DELEGATE" --private-key "$COMPROMISED_KEY" --rpc-url "$FORK")
node build-recover.mjs
node --experimental-strip-types recover.ts

echo "== assertions =="
SAFE_DAI=$(cast call "$DAI" 'balanceOf(address)(uint256)' "$SAFE" --rpc-url "$FORK" | awk '{print $1}')
SAFE_ETH=$(cast balance "$SAFE" --rpc-url "$FORK")
COMP_DAI=$(cast call "$DAI" 'balanceOf(address)(uint256)' "$COMPROMISED" --rpc-url "$FORK" | awk '{print $1}')
COMP_ETH=$(cast balance "$COMPROMISED" --rpc-url "$FORK")
EOA_CODE=$(cast code "$COMPROMISED" --rpc-url "$FORK" | tr 'A-Z' 'a-z')
EXP_CODE="0xef0100$(echo "$DELEGATE" | sed 's/^0x//' | tr 'A-Z' 'a-z')"

fail=0
chk(){ if [ "$1" = "$2" ]; then echo "PASS  $3"; else echo "FAIL  $3 (got '$1' want '$2')"; fail=1; fi; }
chk "$SAFE_DAI" "$DAI_AMOUNT"           "safe received all DAI"
chk "$SAFE_ETH" "5000000000000000000"  "safe received swept native ETH"
chk "$COMP_DAI" "0"                     "compromised DAI drained"
chk "$COMP_ETH" "0"                     "compromised ETH swept"
chk "$EOA_CODE" "$EXP_CODE"             "EOA carries EIP-7702 delegation indicator"
echo
[ "$fail" = "0" ] && echo "E2E PASSED" || { echo "E2E FAILED"; exit 1; }
