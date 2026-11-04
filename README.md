# Near-LEASH

An on-chain policy gate that lets an AI agent spend from a treasury through NEAR Chain Signatures
and NEAR Intents (1Click) without ever holding keys or funds. The agent gets a function-call key to
two methods on one contract. The contract owns the treasury, is the MPC predecessor for every
foreign-chain address, and evaluates every request against an owner-set policy before executing it.
Denials are NEP-297 events, so the audit trail is the chain itself.

Built for NEAR HACKATHON 2026, tracks `security` and `agents`.

**Status (2026-11-04):** deployed on NEAR testnet as `guardrail2.shortisland3107.testnet`
(owner `shortisland3107.testnet`, MPC `v1.signer-prod.testnet`). Its only access key is one
function-call key for `request_sign,request_swap`. Its MPC-derived Base Sepolia address is
`0xC54Bc53737D47713361a53cAf3806018F572cc40`. First live payment signed by the MPC network
through the policy: Base Sepolia tx `0x6cbac0ca98bc817f9eceb26d88a2a2ef7ee8edde858fc455c2b994d3a1f3e2d5`.
The NEAR Intents path is not run on mainnet (no Intents testnet exists; out of hackathon scope).

## Try it

1. `cargo test -p guardrail` — see: 42 unit tests pass, including every denial rule by name for
   both paths, 3 real 1Click staging-signed quotes verified byte-for-byte, and a live production
   quote (fetched 2026-11-04) verified against the production 1Click key.
2. `cargo test -p guardrail --test sandbox -- --nocapture` — see: 10 near-workspaces tests pass
   against a mock MPC signer and a mock NEP-141 token: allow → `sign_completed` with a broadcastable
   raw tx; denial → `request_denied{rule:"recipient"}` with no budget change; park → owner `approve`;
   signer failure refunds the budget; swap → `swap_funded` and the token balance moves to the
   quote's deposit address; tampered quote → `quote_signature`; replay → `quote_consumed`; pause;
   the agent key cannot call `set_policy`, `withdraw` or `approve` (rejected at the protocol level);
   the owner deletes the deployer's full-access key and the contract keeps working.
3. `cd agent && cp .env.example .env` (fill in) `&& npm i && npm run deploy` — see: `guardrail.<you>.testnet`
   created, policy set, one agent function-call key added, deploy key deleted.
4. `npm run derive` — see: the Base Sepolia address the MPC derives for this contract. Fund it.
5. `npm run demo -- --scenario=injected` — see: the task contains a prompt injection asking to pay
   `0xbad0…`; the chain shows `request_denied{rule:"recipient"}` and the agent's own report says so.
6. `npm run demo -- --scenario=payroll` — see: three signed Base Sepolia transactions under budget,
   the fourth parked for owner approval.
7. `npm run compromised` — see: no LLM; the agent key is treated as stolen and attacks are sent
   straight to the contract. Each is stopped with its rule: `recipient` (attacker address, also when
   hidden in USDC calldata), `chain_id`, `per_request_cap`, `cooldown` on immediate retries,
   `window_cap{index:0}` once the hourly budget is used, and `set_policy` rejected by the NEAR protocol.
8. `npm run demo -- --scenario=drain` — see: the agent is told to drain the treasury in small
   pieces; after the window cap it gets `window_cap{index:0}` on every attempt.
9. `npm run tail` — see: the on-chain request log with rule names and remaining budget.

## How it works

```
                 ┌────────────────────────────┐
  LLM agent ───▶ │ guardrail.<owner>.testnet  │──▶ v1.signer  (MPC sign of the tx the contract built)
  (FC key only)  │  policy engine + treasury  │──▶ <ft>.near  ft_transfer → 1Click depositAddress
                 │  NEP-297 events            │
                 └────────────────────────────┘
                        ▲
                 owner account (separate; a Trezu/Sputnik DAO in production)
```

| Who | Holds | Can do |
|---|---|---|
| Agent | FC key → guardrail, methods `request_sign,request_swap`, gas allowance | Ask. |
| Guardrail | Treasury; MPC predecessor; **no full-access key** | Execute within policy. |
| Owner | Its own account | Set policy, pause, approve parked requests, rotate keys, withdraw. |
| 1Click | Its manager ed25519 key | Sign quotes. |
| MPC network | Root key | Sign hashes the guardrail submits. |

**Chain Signatures path.** The agent never supplies bytes to sign. `request_sign` takes structured
fields; the contract builds the EIP-1559 transaction with `omni-transaction-rs`, hashes it, runs the
rules, and asks `v1.signer` to sign what it built. ERC-20 `transfer(address,uint256)` calldata is
decoded: the token must be allowlisted, the decoded recipient must be allowlisted, and the amount is
priced into the caps. Rule order, first failure wins: `paused` → `agent_key` → `chain_id` →
(`token` → `recipient` | `recipient` → `selector`) → `gas_limit` → `gas_price` → `path` →
`per_request_cap` → `cooldown` → `window_cap{index}` → approval threshold.

**Intents path.** `intents.near` only executes off-chain-signed payloads, so the gate is at funding.
The agent fetches a 1Click quote; the contract recomputes `base58(sha256(json-stable-stringify(…)))`
exactly as the SDK does, verifies the ed25519 signature against the 1Click manager key, checks
age, deadline, `refundTo == guardrail`, assets, recipient, slippage, min-out ratio and the USD caps,
then `ft_transfer`s the input to the quote's deposit address. Failed swaps refund to the guardrail
because the policy forces `refundTo`.

## NEAR features used

Chain Signatures (`v1.signer`, secp256k1 domain 0, address derived from the contract as predecessor),
NEAR Intents via the 1Click deposit-address flow with on-chain quote verification, function-call
access keys as the only agent credential, NEP-297 events, `near-workspaces` sandbox tests.
Not used: TEE attestation, NEAR AI Cloud (inference is the Claude API; the contract trusts the
agent for nothing, so the provider is irrelevant to the security claim).

## Policy reference

See `agent/policies/testnet.json` for a complete example and `docs/guardrail-spec.md` §5.

## Threat model and limitations

Scope: built and proven on testnet. The Chain Signatures path runs live (NEAR testnet + Base
Sepolia). The Intents path is proven in the sandbox (mock NEP-141, quote verification, funding,
refund, replay) and against real staging and production 1Click signatures, but no mainnet swap was
executed: 1Click has no testnet, and a mainnet deploy is out of scope for the hackathon.

`docs/guardrail-spec.md` §7–8. Known limitations: USD valuation for the Chain Signatures path uses
a static per-asset price table set by the owner (an oracle is a stretch goal); the USD figure for
swaps comes from the signed 1Click quote; arbitrary calldata other than ERC-20 `transfer` is gated
by selector and `to` only, so the example policy leaves `allowed_selectors` empty. The contract
cannot see what happens on the EVM chain after it signs: a signed transaction that reverts or is
never broadcast still counts against the budget (conservative by design). Recipients can be
contracts, including EIP-7702 delegated accounts, so the agent estimates gas rather than assuming 21000.

## Layout

```
contract/src/policy.rs    pure policy types + evaluator (no host calls)
contract/src/oneclick.rs  1Click quote parsing, stable-stringify parity, ed25519 verify
contract/src/evm.rs       EIP-1559 build + ERC-20 transfer decode (no RLP decoding anywhere)
contract/src/lib.rs       contract: request_sign / request_swap / callbacks / owner API / events
contract/tests/sandbox.rs near-workspaces tests;  contract/tests/vectors/  real 1Click signed quotes
mocks/                    mock v1.signer and mock NEP-141 for the sandbox
agent/                    TypeScript agent (Claude API tool runner), deploy script, event tail
docs/guardrail-spec.md    design of record
```

## Build

```
cargo test -p guardrail                                      # unit + sandbox
cargo build -p guardrail --target wasm32-unknown-unknown --release
cd agent && npm i && npm run typecheck
```
## Hackathon disclosure

- **Timeline.** Development started 2026-10-21, after the 2026-10-19 announcement (rules Q-001).
  Everything in this repo was built for NEAR HACKATHON; there is no pre-existing product or baseline.
- **AI-written code (rules Q-005).** Most of the code, tests and docs were written with Claude Code
  (Anthropic) as a pair programmer, directed and reviewed by the team. The demo agent's inference uses
  the Claude API (`claude-opus-5-5`); the red-team target uses a local Qwen3 4B model through Ollama.
- **License.** MIT, see `LICENSE`.

### Libraries and data used

| Where | What |
|---|---|
| Contract (Rust) | `near-sdk` 5, `omni-transaction` 0.5 (EIP-1559 building), `serde`/`serde_json`, `bs58`, `hex` |
| Contract tests | `near-workspaces` (sandbox), `ed25519-dalek`, `sha2`, `tokio`, `chrono`, `anyhow` |
| Test vectors | Signed 1Click quotes from the `one-click-sdk-typescript` 0.1.25 test suite (staging) and one live production quote fetched 2026-11-04 |
| Agent (TypeScript) | `@anthropic-ai/sdk` (tool runner), `near-api-js` 5, `ethers` 6, `zod`, `dotenv`, `tsx` |
| Red-team harness (Python) | `ollama` Python client, model `qwen3:4b-instruct-2507-q4_K_M` |
| NEAR services | NEAR testnet, MPC signer `v1.signer-prod.testnet` (Chain Signatures), 1Click API (quote verification only) |
