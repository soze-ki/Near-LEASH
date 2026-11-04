# Guardrail — spec v0.1

On-chain policy layer that lets an AI agent move money through NEAR Chain Signatures and NEAR Intents without ever holding keys or funds.
Target: NEAR HACKATHON 2026, tracks `security` (primary), `agents` (secondary).
Status: design frozen on 2026-10-21 after verification checks; contract implemented the same day (41 unit tests). Revised 2026-10-21 (v0.2): ERC-20 transfer decoding, denial storage bound, owner model, agent stack.

## 1. Thesis

Give the agent a *function-call key* to one contract and nothing else. The contract owns the treasury and the MPC-derived foreign-chain addresses. Every outbound value movement is a method call the contract evaluates against a human-set policy before it executes. Denials are on-chain events, so the audit trail is the chain itself.

The security property that makes this real rather than cosmetic: the MPC signer derives keys from `(predecessor_id, path)`. When the policy contract is the predecessor of `v1.signer.sign`, the Ethereum/Bitcoin address is the contract's. There is no second route to a signature for that address.

## 2. Verification results (2026-10-21)

| # | Question | Result | Consequence |
|---|---|---|---|
| 1 | 1Click quote signature scheme | ed25519 detached signature by `ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc` over the UTF-8 bytes of `base58(sha256(json-stable-stringify({request-subset, quote-subset, timestamp})))`. Field subsets are fixed in `quote-signature.ts` (SDK 0.1.25). | Verifiable on-chain with `env::ed25519_verify`. The hard part is reproducing `json-stable-stringify` output byte-for-byte in Rust (sorted keys, omitted `undefined`, JS number formatting). |
| 2 | 1Click / Intents testnet | None. Docs state it three times: "There is no testnet version of NEAR Intents - use small amounts." | Intents path demos on mainnet with small amounts. Contract itself can be tested in sandbox with a mocked signature. |
| 3 | Gas for decoding an EVM tx in-contract | Moot — see 4. Encoding a small EIP-1559 tx + `env::keccak256` is well under 10 TGas. MPC `sign` costs ~7 TGas to submit, requires ≥10 attached, 1 yoctoNEAR deposit; abstract-dao reserves 260 TGas for the full sign round-trip. | Per-call budget: policy check + build + sign fits in one 300 TGas transaction. |
| 4 | Does `omni-transaction-rs` decode RLP? | No. v0.5.0 is build-only: `EVMTransaction::from_json`, `build_for_signing`, `build_with_signature`. No `Decodable` for EVM. | **Design change:** the agent never submits raw RLP. It submits structured fields; the contract builds the transaction, hashes it, and signs *what it built*. No decoder, no parse/sign mismatch. |

Side finding from check 1 research: `intents.near` only executes off-chain-signed payloads (`execute_intents(Vec<MultiPayload>)`), and every registered key on an intents account has full control. A contract cannot author intents and cannot hand the agent a limited intents key. Therefore the Intents path is gated at the *funding* step via the 1Click deposit-address flow, not at signing.

## 3. Architecture

```
                 ┌────────────────────────────┐
  LLM agent ───▶ │ guardrail.<owner>.near     │──▶ v1.signer  (MPC sign)
  (FC key only)  │  policy engine + treasury  │──▶ <ft>.near  ft_transfer → 1Click depositAddress
                 │  NEP-297 events            │
                 └────────────────────────────┘
                        ▲            │
                 owner (full key)    └──▶ indexer/dashboard reads events
```

Components:

1. **`guardrail` contract (Rust, near-sdk-rs).** Holds NEAR and NEP-141 balances. Owns MPC-derived addresses. Exposes two agent-facing methods and an owner-facing policy API. Single contract, no factory for the hackathon.
2. **Agent (TypeScript, Claude API via `@anthropic-ai/sdk` tool use).** Tool-calling loop. Tools: `get_quote` (1Click), `request_swap`, `request_sign`, `read_policy`, `get_budget`. Holds one function-call key: receiver `guardrail.<owner>.near`, methods `request_sign,request_swap`, allowance for gas only. Inference provider is irrelevant to the security claim (the contract does not trust the agent at all); the loop is written against the Anthropic SDK and can be pointed at any OpenAI-compatible endpoint (NEAR AI Cloud) by swapping the client. Not using NEAR AI Cloud or TEE attestation is stated in the README, not implied.
3. **Dashboard (static page).** Reads `guardrail` events via RPC/indexer. Shows every request, allow/deny, policy clause that fired, remaining budget per window.
4. **Owner.** A *separate* NEAR account (`owner` in contract state; a Trezu/Sputnik DAO in production). Sets policy, pauses, rotates agent keys, withdraws. Never in the hot path. The guardrail account itself keeps **no** full-access key after setup: the deployer's key is removed with `delete_account_key` so the only routes in are the owner account (via `predecessor`) and agent function-call keys restricted to two methods.

Key custody:

| Who | Holds | Can do |
|---|---|---|
| Agent | FC key → guardrail, 2 methods, gas allowance | Ask. |
| Guardrail | Treasury; is predecessor for MPC; **no full-access key** | Execute within policy. |
| Owner | Its own account's keys (or a DAO) | Set policy, pause, withdraw, approve, rotate keys. |
| 1Click | Its manager ed25519 key | Sign quotes. |
| MPC network | Root key | Sign hashes the guardrail submits. |

## 4. Contract interface

### Agent-facing

```rust
/// Build, policy-check, and MPC-sign an EVM transaction. Never accepts RLP.
pub fn request_sign(&mut self, req: SignRequest) -> Promise;

pub struct SignRequest {
    pub chain_id: u64,
    pub to: String,            // 0x-hex, 20 bytes
    pub value: U128,           // wei
    pub data: Option<Base64VecU8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: U128,
    pub max_priority_fee_per_gas: U128,
    pub path: String,          // derivation path label, must be in policy.paths
    pub intent_note: String,   // free text from the agent, logged, never trusted
}

/// Verify a 1Click quote signature, policy-check it, and transfer the input
/// asset to the quote's depositAddress. Never signs an intent.
pub fn request_swap(&mut self, quote: OneClickQuoteResponse) -> Promise;
```

Both are `#[payable]`-free (deposit must be 0) so a function-call key can call them. Both return a `RequestId` in the event stream whether allowed or denied. Denials must not panic (a panic rolls back the receipt and the event with it): they return `Err(Denied { rule })` through a non-panicking result type and emit the event in the same receipt.

### Owner-facing

```rust
pub fn set_policy(&mut self, policy: Policy);          // full replace, versioned
pub fn pause(&mut self); pub fn unpause(&mut self);    // kill switch
pub fn add_agent_key(&mut self, pk: PublicKey);        // AddKey FC, methods fixed; registered in the callback only if AddKey succeeded
pub fn remove_agent_key(&mut self, pk: PublicKey);     // unregistered immediately, then DeleteKey
pub fn delete_account_key(&mut self, pk: PublicKey);   // remove the deployer's full-access key after setup
pub fn withdraw(&mut self, token: Option<AccountId>, to: AccountId, amount: U128);
pub fn approve(&mut self, request_id: u64);            // for requests parked in `needs_approval`
```

### View

```rust
pub fn get_policy(&self) -> Policy;
pub fn get_budget(&self) -> BudgetView;                // spent / remaining per window
pub fn get_request(&self, id: u64) -> Option<RequestRecord>;
pub fn derived_address(&self, chain: String, path: String) -> String;  // what the agent is allowed to think it "owns"
```

### Events (NEP-297, `standard: "guardrail", version: "1.0.0"`)

`request_allowed`, `request_denied { rule, detail }`, `request_parked`, `request_approved`, `sign_completed { request_id, sig }`, `sign_failed`, `swap_funded { request_id, deposit_address, amount }`, `policy_updated { version }`, `paused`, `unpaused`.

## 5. Policy schema

```json
{
  "version": 3,
  "paused": false,
  "windows": [
    { "seconds": 3600,  "max_usd_cents": 5000 },
    { "seconds": 86400, "max_usd_cents": 25000 }
  ],
  "per_request_max_usd_cents": 2000,
  "approval_threshold_usd_cents": 1000,
  "cooldown_seconds": 60,
  "evm": {
    "allowed_chain_ids": [8453, 42161],
    "allowed_recipients": ["0x…", "0x…"],
    "allowed_selectors": [],
    "erc20_tokens": [
      { "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "decimals": 6, "usd_cents_per_token": 100 }
    ],
    "max_gas_limit": 300000,
    "max_fee_per_gas_wei": 50000000000,
    "paths": ["treasury-base", "treasury-arb"],
    "usd_cents_per_native": 300000
  },
  "intents": {
    "allowed_origin_assets": ["nep141:usdc.near"],
    "allowed_destination_assets": ["nep141:eth.omft.near", "nep141:base-0x….omft.near"],
    "allowed_recipients": ["0x…"],
    "max_slippage_bps": 100,
    "min_amount_out_ratio_bps": 9800,
    "max_quote_age_seconds": 120,
    "quote_signer": "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc"
  }
}
```

**ERC-20 transfers are decoded, not allowlisted by selector.** When calldata starts with `transfer(address,uint256)` (`0xa9059cbb`) the contract requires exactly 68 ABI bytes, decodes the recipient and amount, requires the token contract (`to`) to be in `erc20_tokens`, applies `allowed_recipients` to the *decoded* recipient, and values the amount with the token's static price. Without this an agent could move any amount of any token to any address with `value: 0` and only gas counted toward the caps. `allowed_selectors` is for other calls and never opens the transfer path; for such calls `allowed_recipients` applies to `to` and only the native value is priced, so keep that list empty unless you accept that.

USD valuation for the Chain Signatures path needs a price. Hackathon scope: owner sets a static `usd_per_unit` table in policy per asset; a Pyth/OutLayer oracle is a stretch goal and noted as such in the README. For the Intents path, `amountInUsd` comes inside the signed 1Click payload, so it is trustworthy to the extent 1Click is.

## 6. Flows

### Chain Signatures path

1. Agent calls `request_sign(req)`.
2. Contract: `assert!(!paused)`; predecessor is a registered agent key? (NEAR exposes `signer_account_pk` — compare against `agent_keys`).
3. Build `EVMTransaction` from `req` via `omni-transaction-rs` (`from_json` or struct literal). Hash with `keccak256(build_for_signing())`.
4. Evaluate rules in fixed order; first failure wins and is the `rule` in the denial event: `paused` → `agent_key` → `chain_id` → (ERC-20 transfer: `token` → `recipient` on decoded address | other: `recipient` on `to` → `selector`) → `gas_limit` → `gas_price` → `path` → `per_request_cap` → `cooldown` → `window_cap{index}` → `approval_threshold`. Malformed input (bad address, oversize calldata, malformed transfer ABI) is `malformed`.
5. If under threshold: debit window counters, store `RequestRecord{status: Signing}`, emit `request_allowed`, call `v1.signer.sign{request: {payload_v2: {Ecdsa: <hash hex>}, path, domain_id: 0}}` (secp256k1 domain is 0, ed25519 is 1 — per `SignRequestArgs` and chainsig.js) with 1 yocto and ≥250 TGas, then `.then(on_sign)`.
6. `on_sign` (private): on success store signature, emit `sign_completed`, return the `(r,s,v)` so the agent's tool call result contains it. On failure refund the window debit, emit `sign_failed`.
7. Agent assembles `build_with_signature` client-side (or the contract returns the full raw tx) and broadcasts to the EVM chain. Broadcasting is outside the guardrail; the signature is what was gated.

Above threshold: store `RequestRecord{status: Parked}`, emit `request_parked`, return. Owner calls `approve(id)` → steps 5–6 run with the stored request. Parked requests expire after `cooldown_seconds * 60`.

### Intents path (1Click deposit-address)

1. Agent calls 1Click `POST /v0/quote` with `dry: false`, `refundTo = guardrail account`, `recipient` from policy. Gets `QuoteResponse` with `signature`, `timestamp`, `quote.depositAddress`.
2. Agent calls `request_swap(quote_response)`.
3. Contract recomputes the canonical hash (section 2, check 1), verifies `ed25519_verify(sig, msg, policy.intents.quote_signer)`. Any failure → `request_denied{rule: "quote_signature"}`.
4. Rules in order: `paused` → `agent_key` → `quote_signature` → `quote_age` (`timestamp` vs `block_timestamp`) → `quote_deadline` → `refund_to == self` → `origin_asset` → `destination_asset` → `recipient` → `slippage` → `min_amount_out_ratio` (`minAmountOut / amountOut`) → `per_request_cap` (`amountInUsd`) → `cooldown` → `window_caps` → `approval_threshold`.
5. Allowed: debit counters, emit `request_allowed`, `ft_transfer(depositAddress, amountIn, memo = depositMemo)` on the origin NEP-141 contract (1 yocto, ~30 TGas), `.then(on_swap_funded)`.
6. `on_swap_funded`: on success emit `swap_funded`; on failure refund the window debit, emit `swap_failed`.
7. Agent polls 1Click `GET /v0/status?depositAddress=…` to report completion. 1Click's refund on failure returns to `refundTo`, which policy forces to be the guardrail — so a failed swap cannot leak funds to an agent-chosen address.

## 7. Threat model

| Threat | Mitigation |
|---|---|
| Agent key stolen or agent prompt-injected into sending funds to attacker | Recipient allowlist, selector allowlist, per-request cap, window caps, cooldown. Worst case loss = `windows[0].max` before owner notices; `pause` stops it. |
| Agent submits RLP that decodes to something other than what the policy saw | Not possible: contract builds the tx, agent never supplies bytes. |
| Agent hides a transfer in calldata (`to` = token contract, `value` = 0, recipient and amount inside `transfer(address,uint256)`) | ERC-20 transfer is decoded; token must be allowlisted, decoded recipient must be allowlisted, amount is priced into the caps. Malformed ABI is denied. |
| Agent forges or edits a 1Click quote (change `depositAddress` to its own) | ed25519 verification of the full signed payload incl. `depositAddress`; `refundTo` forced to self. |
| Replay of an old valid quote | `quote_age` rule + 1Click `deadline`; store hash of consumed quotes, reject duplicates. |
| Agent splits a large transfer into many small ones | Window caps across all requests; cooldown. |
| Agent drains via gas (`max_fee_per_gas` huge, value 0) | `max_gas_limit`, `max_fee_per_gas_gwei` rules; gas value counted toward USD caps. |
| EVM nonce games (agent supplies stale/future nonce to get a signature it broadcasts later) | Signatures for a stale nonce are useless after the real nonce passes it; a future-nonce signature is still constrained by the policy that approved it. Document; optionally let owner pin `expected_nonce` per path. |
| MPC callback fails / times out after counters debited | Callback refunds window debit; state is written before the promise so a panic in the callback cannot roll back the debit without the refund logic — design the callback to never panic. |
| Storage griefing (agent spams denied requests to bloat state) | Agent FC key has no deposit allowance. Denied records store only kind label, rule and payload hash (never the request or the 2 KB quote). Records are a ring of 2000: allocating id *n* evicts record *n−2000* unless it is parked/signing/funding. Total calls are bounded by the key's gas allowance (1 NEAR). |
| Owner tricked into a policy update that clears the caps | Spend counters survive `set_policy` unless the window layout itself changes (`policy_updated{budget_reset}` says which). |
| Deployer full-access key on the guardrail account is a second route to the treasury | Owner is a separate account; after setup the owner calls `delete_account_key` on the deployer key. README setup step checks `view_access_key_list` shows only agent FC keys. |
| Owner key compromise | Out of scope; owner is already a separate account, so pointing it at a Trezu/Sputnik DAO is a config change, not a redesign. |
| Sybil / multiple agent keys | All agent keys share one budget; keys are allow-listed by owner. |
| Front-running the deposit address | Deposit address is 1Click's, unique per quote; funds only move to it. Nothing for a third party to front-run. |
| Price staleness for USD caps (CS path) | Static table is a known weakness; documented. Caps also exist in native units as a floor. |

## 8. Open risks

1. **`json-stable-stringify` parity.** Must match byte-for-byte or every verification fails. Mitigation: a Rust canonicalizer with unit tests against vectors generated by the real SDK (`hashQuote`). Numbers: all 1Click numeric fields in the signed subset are integers or strings; confirm by generating 20 real quotes and diffing. If any float appears, the fallback is to pass the canonical string in from the agent and verify that the string's parsed fields equal the typed fields the contract checks — still sound, slightly more gas.
2. **Mainnet-only Intents.** Demo costs real money. Budget: £50 in USDC on NEAR, swaps of $1–5. Sandbox tests mock the signer key with one the test owns.
3. **MPC testnet liveness.** `v1.signer-prod.testnet` is sometimes slow. Record demo on a good day; have sandbox tests that stub the signer.
4. **Gas headroom.** Contract-side JSON of a full `QuoteResponse` is ~2 KB; parsing + canonicalize + sha256 + ed25519_verify + ft_transfer should sit around 40–60 TGas. Measure early.

## 9. Test matrix

Unit (`cargo test`): every rule in section 6 step 4 for both paths, allow and deny, boundary values; canonicalizer vectors; window rollover; cooldown; parked→approved→expired.
Sandbox (`near-workspaces`): deploy guardrail + a mock `v1.signer` that returns a fixed signature; mock NEP-141; run the full allow flow, the deny flow, the callback-failure refund, the pause.
Testnet: real `v1.signer-prod.testnet`, EVM path on Base Sepolia (chain 84532), end-to-end with the agent.
Mainnet: out of scope for the hackathon (decided 2026-11-04). Intents path proven in sandbox and against real staging + production signed quotes.

## 10. Build plan

Pre-window (local, unpushed): contract crate skeleton, policy types + evaluator with unit tests, canonicalizer with SDK vectors, ERC-20 decoding, mock signer, sandbox tests.
Nov 1–14 (public): fresh repo, push; testnet deploy; agent (TS, Claude API); event-log CLI (dashboard only if time allows); prompt-injection demo script; README; demo video; submit. No mainnet.

## 11. README skeleton (judge format)

```
# Guardrail
One sentence. Problem. What it is.

## Try it (5 min)
1. `npm i && npm run sandbox` — see: 12 tests pass, including 7 denials with rule names.
2. `npm run demo:agent -- --scenario=injected` — see: agent attempts to send 1 ETH to 0xBAD…, chain shows `request_denied{rule:"recipient"}`.
3. `npm run demo:agent -- --scenario=payroll` — see: three signed Base txs under budget, fourth parked for approval.
4. Open dashboard — see: budget bars, event log with tx links.

## How it works  (architecture diagram, key custody table)
## NEAR features used  (Chain Signatures, Intents via 1Click, function-call keys, NEP-297, near-workspaces)
## Policy reference
## Threat model
## Limitations
```

## 12. Submission mapping

`tracks: ["security", "agents"]`. Hints matched: AGENT SECURITY, FUNCTION CALL KEYS, CHAIN SIGNATURES, NEAR INTENTS. Not using TEE attestation or NEAR AI Cloud; say so rather than imply it. Differentiation from OutLayer (listed partner, "secure transactions for AI agents"): here the policy engine and the MPC predecessor are the same on-chain account, so the derived addresses cannot be reached by any path that skips the policy.
