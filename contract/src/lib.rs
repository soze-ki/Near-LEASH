//! Guardrail: on-chain policy gate between an AI agent and NEAR Chain
//! Signatures / NEAR Intents (1Click).
//!
//! The agent holds a function-call key scoped to `request_sign` and
//! `request_swap` on this account and nothing else. This contract owns the
//! treasury and is the predecessor of every MPC `sign` call, so the derived
//! foreign-chain addresses belong to it. See `guardrail-spec.md`.

pub mod evm;
pub mod oneclick;
pub mod policy;

use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json, Value};
use near_sdk::store::{IterableSet, LookupMap, LookupSet};
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError, PromiseOrValue, PublicKey,
};

use evm::SignRequest;
use oneclick::{QuoteFacts, QuoteResponse};
use policy::{BudgetState, Decision, EvmFacts, Policy, Rule, SwapFacts};

const GAS_MPC_SIGN: Gas = Gas::from_tgas(250);
const GAS_ON_SIGN: Gas = Gas::from_tgas(10);
const GAS_FT_TRANSFER: Gas = Gas::from_tgas(30);
const GAS_ON_SWAP: Gas = Gas::from_tgas(10);
const GAS_ON_KEY: Gas = Gas::from_tgas(5);
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);
const AGENT_KEY_ALLOWANCE: NearToken = NearToken::from_near(1);
const AGENT_METHODS: &str = "request_sign,request_swap";
const EVENT_STANDARD: &str = "guardrail";
const EVENT_VERSION: &str = "1.0.0";
/// Parked requests expire after this.
const PARK_TTL_NS: u64 = 24 * 3600 * 1_000_000_000;
/// Request records are a ring: when a new id is allocated, the record
/// `MAX_RECORDS` ids back is evicted unless it is still in flight (parked,
/// signing, funding). Bounds storage an agent key can make the contract pay for.
const MAX_RECORDS: u64 = 2000;

#[derive(BorshStorageKey)]
#[near(serializers = [borsh])]
enum StorageKey {
    AgentKeys,
    Requests,
    ConsumedQuotes,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Denied,
    Parked,
    Expired,
    Signing,
    Signed,
    SignFailed,
    Funding,
    Funded,
    FundFailed,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub enum Kind {
    Sign(SignRequest),
    /// Full 1Click response JSON, kept so `approve` can re-execute it.
    Swap(String),
    /// Denied requests keep only the kind label ("sign" / "swap") and the
    /// payload hash, never the payload, so denials cannot bloat storage.
    Denied(String),
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct RequestRecord {
    pub id: u64,
    pub kind: Kind,
    pub status: Status,
    pub rule: Option<Rule>,
    pub usd_cents: u64,
    pub created_ns: u64,
    pub agent_pk: PublicKey,
    /// hex keccak of the unsigned EVM tx, or sha256 of the canonical quote
    pub payload_hash: String,
    /// JSON of the MPC signature / ft_transfer outcome, once known
    pub result: Option<String>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct EvmSignature {
    pub r: String,
    pub s: String,
    pub recovery_id: u8,
}

/// Returned to the agent from both request methods and both callbacks.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct RequestOutcome {
    pub request_id: u64,
    pub status: Status,
    pub rule: Option<Rule>,
    pub signature: Option<EvmSignature>,
    /// Broadcastable raw EIP-1559 tx (0x hex) when signed.
    pub raw_tx: Option<String>,
    pub deposit_address: Option<String>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct BudgetView {
    pub windows: Vec<WindowView>,
    pub last_request_ns: u64,
    pub cooldown_remaining_s: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct WindowView {
    pub seconds: u64,
    pub max_usd_cents: u64,
    pub spent_usd_cents: u64,
    pub remaining_usd_cents: u64,
    pub resets_in_s: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Guardrail {
    owner: AccountId,
    mpc: AccountId,
    paused: bool,
    policy: Policy,
    budget: BudgetState,
    agent_keys: IterableSet<PublicKey>,
    requests: LookupMap<u64, RequestRecord>,
    next_id: u64,
    consumed_quotes: LookupSet<Vec<u8>>,
}

fn emit(event: &str, data: Value) {
    let e = json!({
        "standard": EVENT_STANDARD,
        "version": EVENT_VERSION,
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{e}"));
}

#[near]
impl Guardrail {
    #[init]
    pub fn new(owner: AccountId, mpc: AccountId, policy: Policy) -> Self {
        let now = env::block_timestamp();
        Self {
            owner,
            mpc,
            paused: false,
            budget: BudgetState::for_policy(&policy, now),
            policy,
            agent_keys: IterableSet::new(StorageKey::AgentKeys),
            requests: LookupMap::new(StorageKey::Requests),
            next_id: 1,
            consumed_quotes: LookupSet::new(StorageKey::ConsumedQuotes),
        }
    }

    // ------------------------------------------------------------------
    // Agent-facing
    // ------------------------------------------------------------------

    /// Build, policy-check and MPC-sign an EVM transaction.
    /// Callable with the agent's function-call key. Never panics on a denial.
    pub fn request_sign(&mut self, req: SignRequest) -> PromiseOrValue<RequestOutcome> {
        require!(env::attached_deposit().is_zero(), "no deposit");
        let now = env::block_timestamp();
        self.budget.roll(&self.policy, now);
        let agent_pk = env::signer_account_pk();
        let agent_ok = self.is_agent_call(&agent_pk);
        let id = self.alloc_id();

        let built = match evm::build(&req) {
            Ok(b) => b,
            Err(e) => {
                return PromiseOrValue::Value(self.deny(id, Kind::Sign(req), agent_pk, 0, Rule::Malformed, now, format!("{e:?}")));
            }
        };
        let native_usd = evm::wei_to_usd_cents(evm::max_native_cost_wei(&req), self.policy.evm.usd_cents_per_native);
        // Unknown token => 0 here; `evaluate_sign` denies it with Rule::Token before any budget rule.
        let token_usd = built
            .erc20
            .as_ref()
            .and_then(|t| policy::erc20_usd_cents(&self.policy, &built.to_norm, t.amount))
            .unwrap_or(0);
        let usd = native_usd.saturating_add(token_usd);
        let facts = EvmFacts {
            chain_id: req.chain_id,
            to: &built.to_norm,
            selector: built.selector.as_deref(),
            erc20: built.erc20.as_ref().map(|t| policy::Erc20Facts { token: &built.to_norm, recipient: &t.recipient }),
            gas_limit: req.gas_limit,
            max_fee_per_gas: req.max_fee_per_gas.0,
            path: &req.path,
            usd_cents: usd,
        };
        let decision = policy::evaluate_sign(&self.policy, &self.budget, now, self.paused, agent_ok, &facts);
        let hash = hex::encode(env::keccak256(&built.unsigned));

        match decision {
            Decision::Deny(rule) => {
                PromiseOrValue::Value(self.deny(id, Kind::Sign(req), agent_pk, usd, rule, now, hash))
            }
            Decision::Park => {
                self.park(id, Kind::Sign(req), agent_pk, usd, now, hash);
                PromiseOrValue::Value(RequestOutcome { request_id: id, status: Status::Parked, rule: None, signature: None, raw_tx: None, deposit_address: None })
            }
            Decision::Allow => {
                self.budget.commit(now, usd);
                self.requests.insert(id, RequestRecord { id, kind: Kind::Sign(req.clone()), status: Status::Signing, rule: None, usd_cents: usd, created_ns: now, agent_pk, payload_hash: hash.clone(), result: None });
                let recipient = built.erc20.as_ref().map(|t| t.recipient.clone()).unwrap_or_else(|| built.to_norm.clone());
                emit("request_allowed", json!({"request_id": id, "kind": "sign", "usd_cents": usd, "payload_hash": hash, "to": built.to_norm, "recipient": recipient, "erc20_amount": built.erc20.as_ref().map(|t| t.amount.to_string()), "chain_id": req.chain_id, "note": req.intent_note}));
                PromiseOrValue::Promise(self.mpc_sign(id, &hash, &req.path))
            }
        }
    }

    /// Verify a 1Click quote, policy-check it, and fund its deposit address.
    /// Callable with the agent's function-call key. Never panics on a denial.
    pub fn request_swap(&mut self, quote: QuoteResponse) -> PromiseOrValue<RequestOutcome> {
        require!(env::attached_deposit().is_zero(), "no deposit");
        let now = env::block_timestamp();
        self.budget.roll(&self.policy, now);
        let agent_pk = env::signer_account_pk();
        let agent_ok = self.is_agent_call(&agent_pk);
        let id = self.alloc_id();
        let raw = serde_json::to_string(&quote).expect("quote serialises");

        let canonical = oneclick::canonical_string(&quote);
        let canon_hash = env::sha256(canonical.as_bytes());
        let hash_hex = hex::encode(&canon_hash);

        let Some(f) = QuoteFacts::from_response(&quote) else {
            return PromiseOrValue::Value(self.deny(id, Kind::Swap(raw), agent_pk, 0, Rule::Malformed, now, hash_hex));
        };
        if f.dry {
            return PromiseOrValue::Value(self.deny(id, Kind::Swap(raw), agent_pk, 0, Rule::Malformed, now, hash_hex));
        }
        let sig_ok = oneclick::verify_quote(&quote, &self.policy.intents.quote_signer, |b| env::sha256(b), |s, m, pk| env::ed25519_verify(s, m, pk));
        let ts = oneclick::rfc3339_to_ns(&quote.timestamp).unwrap_or(0);
        let deadline = oneclick::rfc3339_to_ns(&f.quote_deadline).unwrap_or(0);
        let self_id = env::current_account_id();
        let facts = SwapFacts {
            signature_ok: sig_ok,
            already_consumed: self.consumed_quotes.contains(&canon_hash),
            quote_timestamp_ns: ts,
            quote_deadline_ns: deadline,
            refund_to: &f.refund_to,
            self_account: self_id.as_str(),
            origin_asset: &f.origin_asset,
            destination_asset: &f.destination_asset,
            recipient: &f.recipient,
            slippage_bps: f.slippage_bps,
            amount_out: f.amount_out,
            min_amount_out: f.min_amount_out,
            usd_cents: f.amount_in_usd_cents,
        };
        let decision = policy::evaluate_swap(&self.policy, &self.budget, now, self.paused, agent_ok, &facts);
        let usd = f.amount_in_usd_cents;

        match decision {
            Decision::Deny(rule) => PromiseOrValue::Value(self.deny(id, Kind::Swap(raw), agent_pk, usd, rule, now, hash_hex)),
            Decision::Park => {
                self.park(id, Kind::Swap(raw), agent_pk, usd, now, hash_hex);
                PromiseOrValue::Value(RequestOutcome { request_id: id, status: Status::Parked, rule: None, signature: None, raw_tx: None, deposit_address: Some(f.deposit_address) })
            }
            Decision::Allow => {
                self.budget.commit(now, usd);
                self.consumed_quotes.insert(canon_hash);
                self.requests.insert(id, RequestRecord { id, kind: Kind::Swap(raw), status: Status::Funding, rule: None, usd_cents: usd, created_ns: now, agent_pk, payload_hash: hash_hex.clone(), result: None });
                emit("request_allowed", json!({"request_id": id, "kind": "swap", "usd_cents": usd, "payload_hash": hash_hex, "deposit_address": f.deposit_address, "origin_asset": f.origin_asset, "destination_asset": f.destination_asset, "amount_in": f.amount_in.to_string()}));
                PromiseOrValue::Promise(self.fund_swap(id, &f))
            }
        }
    }

    // ------------------------------------------------------------------
    // Callbacks
    // ------------------------------------------------------------------

    #[private]
    pub fn on_sign(&mut self, request_id: u64, #[callback_result] res: Result<Value, PromiseError>) -> RequestOutcome {
        let mut rec = self.requests.get(&request_id).cloned().expect("request");
        let Kind::Sign(req) = &rec.kind else { env::panic_str("kind") };
        match res.ok().and_then(parse_mpc_signature) {
            Some(sig) => {
                let raw_tx = evm::build(req).ok().map(|b| {
                    let r = <[u8; 32]>::try_from(hex::decode(&sig.r).unwrap_or_default()).unwrap_or([0; 32]);
                    let s = <[u8; 32]>::try_from(hex::decode(&sig.s).unwrap_or_default()).unwrap_or([0; 32]);
                    format!("0x{}", hex::encode(evm::with_signature(&b.tx, r, s, sig.recovery_id)))
                });
                rec.status = Status::Signed;
                rec.result = Some(serde_json::to_string(&sig).unwrap());
                self.requests.insert(request_id, rec);
                emit("sign_completed", json!({"request_id": request_id, "r": sig.r, "s": sig.s, "recovery_id": sig.recovery_id}));
                RequestOutcome { request_id, status: Status::Signed, rule: None, signature: Some(sig), raw_tx, deposit_address: None }
            }
            None => {
                self.budget.refund(rec.usd_cents);
                rec.status = Status::SignFailed;
                self.requests.insert(request_id, rec);
                emit("sign_failed", json!({"request_id": request_id}));
                RequestOutcome { request_id, status: Status::SignFailed, rule: None, signature: None, raw_tx: None, deposit_address: None }
            }
        }
    }

    #[private]
    pub fn on_swap_funded(&mut self, request_id: u64, deposit_address: String, #[callback_result] res: Result<(), PromiseError>) -> RequestOutcome {
        let mut rec = self.requests.get(&request_id).cloned().expect("request");
        match res {
            Ok(()) => {
                rec.status = Status::Funded;
                self.requests.insert(request_id, rec);
                emit("swap_funded", json!({"request_id": request_id, "deposit_address": deposit_address}));
                RequestOutcome { request_id, status: Status::Funded, rule: None, signature: None, raw_tx: None, deposit_address: Some(deposit_address) }
            }
            Err(_) => {
                self.budget.refund(rec.usd_cents);
                // allow the same quote to be retried while it is still valid
                if let Ok(h) = hex::decode(&rec.payload_hash) {
                    self.consumed_quotes.remove(&h);
                }
                rec.status = Status::FundFailed;
                self.requests.insert(request_id, rec);
                emit("swap_failed", json!({"request_id": request_id}));
                RequestOutcome { request_id, status: Status::FundFailed, rule: None, signature: None, raw_tx: None, deposit_address: Some(deposit_address) }
            }
        }
    }

    // ------------------------------------------------------------------
    // Owner-facing
    // ------------------------------------------------------------------

    pub fn set_policy(&mut self, policy: Policy) {
        self.assert_owner();
        require!(policy.version > self.policy.version, "policy version must increase");
        let now = env::block_timestamp();
        // Keep spend counters across a policy update unless the window layout
        // changed; otherwise a version bump would silently clear the caps.
        let windows_changed = policy.windows != self.policy.windows;
        self.policy = policy;
        if windows_changed {
            self.budget = BudgetState::for_policy(&self.policy, now);
        } else {
            self.budget.roll(&self.policy, now);
        }
        emit("policy_updated", json!({"version": self.policy.version, "budget_reset": windows_changed}));
    }

    pub fn pause(&mut self) {
        self.assert_owner();
        self.paused = true;
        emit("paused", json!({}));
    }

    pub fn unpause(&mut self) {
        self.assert_owner();
        self.paused = false;
        emit("unpaused", json!({}));
    }

    /// Add `public_key` to this account as a function-call key restricted to
    /// `request_sign,request_swap` with a gas allowance. The key is registered
    /// as an agent key only once the AddKey action has succeeded.
    pub fn add_agent_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        require!(!self.agent_keys.contains(&public_key), "already an agent key");
        Promise::new(env::current_account_id())
            .add_access_key_allowance(
                public_key.clone(),
                Allowance::limited(AGENT_KEY_ALLOWANCE).expect("non-zero"),
                env::current_account_id(),
                AGENT_METHODS.to_string(),
            )
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_KEY).on_agent_key_added(public_key))
    }

    #[private]
    pub fn on_agent_key_added(&mut self, public_key: PublicKey, #[callback_result] res: Result<(), PromiseError>) -> bool {
        match res {
            Ok(()) => {
                self.agent_keys.insert(public_key.clone());
                emit("agent_key_added", json!({"public_key": public_key}));
                true
            }
            Err(_) => {
                emit("agent_key_add_failed", json!({"public_key": public_key}));
                false
            }
        }
    }

    /// Unregister an agent key (effective immediately) and delete it from the account.
    pub fn remove_agent_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        self.agent_keys.remove(&public_key);
        emit("agent_key_removed", json!({"public_key": public_key}));
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    /// Delete any access key from this account. Intended for removing the
    /// deployer's full-access key after setup so the owner account and the
    /// agent function-call keys are the only routes in (spec §3).
    pub fn delete_account_key(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        self.agent_keys.remove(&public_key);
        emit("account_key_deleted", json!({"public_key": public_key}));
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    /// Execute a parked request. Budget rules are re-checked at approval time.
    pub fn approve(&mut self, request_id: u64) -> PromiseOrValue<RequestOutcome> {
        self.assert_owner();
        let now = env::block_timestamp();
        self.budget.roll(&self.policy, now);
        let mut rec = self.requests.get(&request_id).cloned().expect("request");
        require!(rec.status == Status::Parked, "not parked");
        if now.saturating_sub(rec.created_ns) > PARK_TTL_NS {
            rec.status = Status::Expired;
            self.requests.insert(request_id, rec);
            emit("request_expired", json!({"request_id": request_id}));
            return PromiseOrValue::Value(RequestOutcome { request_id, status: Status::Expired, rule: None, signature: None, raw_tx: None, deposit_address: None });
        }
        let budget_check = policy::evaluate_budget_only(&self.policy, &self.budget, now, self.paused, rec.usd_cents);
        if let Decision::Deny(rule) = budget_check {
            emit("approve_denied", json!({"request_id": request_id, "rule": rule}));
            return PromiseOrValue::Value(RequestOutcome { request_id, status: Status::Parked, rule: Some(rule), signature: None, raw_tx: None, deposit_address: None });
        }
        self.budget.commit(now, rec.usd_cents);
        emit("request_approved", json!({"request_id": request_id, "usd_cents": rec.usd_cents}));
        match rec.kind.clone() {
            Kind::Denied(_) => env::panic_str("not parked"),
            Kind::Sign(req) => {
                rec.status = Status::Signing;
                let hash = rec.payload_hash.clone();
                self.requests.insert(request_id, rec);
                PromiseOrValue::Promise(self.mpc_sign(request_id, &hash, &req.path))
            }
            Kind::Swap(raw) => {
                let quote: QuoteResponse = serde_json::from_str(&raw).expect("stored quote");
                let f = QuoteFacts::from_response(&quote).expect("stored facts");
                let deadline = oneclick::rfc3339_to_ns(&f.quote_deadline).unwrap_or(0);
                if deadline <= now {
                    self.budget.refund(rec.usd_cents);
                    rec.status = Status::Expired;
                    self.requests.insert(request_id, rec);
                    emit("request_expired", json!({"request_id": request_id, "reason": "quote_deadline"}));
                    return PromiseOrValue::Value(RequestOutcome { request_id, status: Status::Expired, rule: Some(Rule::QuoteDeadline), signature: None, raw_tx: None, deposit_address: None });
                }
                if let Ok(h) = hex::decode(&rec.payload_hash) {
                    self.consumed_quotes.insert(h);
                }
                rec.status = Status::Funding;
                self.requests.insert(request_id, rec);
                PromiseOrValue::Promise(self.fund_swap(request_id, &f))
            }
        }
    }

    /// Owner withdrawal of NEAR (`token: None`) or a NEP-141 balance.
    pub fn withdraw(&mut self, token: Option<AccountId>, to: AccountId, amount: U128) -> Promise {
        self.assert_owner();
        emit("withdraw", json!({"token": token, "to": to, "amount": amount}));
        match token {
            None => Promise::new(to).transfer(NearToken::from_yoctonear(amount.0)),
            Some(t) => Promise::new(t).function_call(
                "ft_transfer",
                json!({"receiver_id": to, "amount": amount, "memo": "guardrail withdraw"}).to_string().into_bytes(),
                ONE_YOCTO,
                GAS_FT_TRANSFER,
            ),
        }
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    pub fn get_policy(&self) -> Policy {
        self.policy.clone()
    }
    pub fn is_paused(&self) -> bool {
        self.paused
    }
    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }
    pub fn get_mpc(&self) -> AccountId {
        self.mpc.clone()
    }
    pub fn get_agent_keys(&self) -> Vec<PublicKey> {
        self.agent_keys.iter().cloned().collect()
    }
    pub fn get_request(&self, request_id: u64) -> Option<RequestRecord> {
        self.requests.get(&request_id).cloned()
    }
    /// Next id that will be allocated; ids below it (and above `next_id - MAX_RECORDS`) may exist.
    pub fn get_next_id(&self) -> u64 {
        self.next_id
    }
    /// Page of records, newest first, starting at `before_id` (exclusive; 0 = newest).
    pub fn get_requests(&self, before_id: u64, limit: u64) -> Vec<RequestRecord> {
        let start = if before_id == 0 { self.next_id } else { before_id };
        (1..start).rev().take(limit.min(100) as usize).filter_map(|i| self.requests.get(&i).cloned()).collect()
    }
    pub fn get_budget(&self) -> BudgetView {
        let now = env::block_timestamp();
        let mut b = self.budget.clone();
        b.roll(&self.policy, now);
        let windows = b
            .windows
            .iter()
            .zip(&self.policy.windows)
            .map(|(w, c)| WindowView {
                seconds: c.seconds,
                max_usd_cents: c.max_usd_cents,
                spent_usd_cents: w.spent_usd_cents,
                remaining_usd_cents: c.max_usd_cents.saturating_sub(w.spent_usd_cents),
                resets_in_s: (c.seconds * 1_000_000_000).saturating_sub(now.saturating_sub(w.start_ns)) / 1_000_000_000,
            })
            .collect();
        let cd = self.policy.cooldown_seconds * 1_000_000_000;
        BudgetView {
            windows,
            last_request_ns: b.last_request_ns,
            cooldown_remaining_s: if b.last_request_ns == 0 { 0 } else { cd.saturating_sub(now.saturating_sub(b.last_request_ns)) / 1_000_000_000 },
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    /// True when the call came through a registered agent function-call key.
    /// Such a call has predecessor == this account (the key lives here).
    fn is_agent_call(&self, pk: &PublicKey) -> bool {
        env::predecessor_account_id() == env::current_account_id() && self.agent_keys.contains(pk)
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        if id > MAX_RECORDS {
            let old = id - MAX_RECORDS;
            let in_flight = matches!(
                self.requests.get(&old).map(|r| &r.status),
                Some(Status::Parked | Status::Signing | Status::Funding)
            );
            if !in_flight {
                self.requests.remove(&old);
            }
        }
        id
    }

    fn deny(&mut self, id: u64, kind: Kind, agent_pk: PublicKey, usd: u64, rule: Rule, now: u64, hash: String) -> RequestOutcome {
        let kind_s = match &kind { Kind::Sign(_) => "sign", Kind::Swap(_) => "swap", Kind::Denied(k) => k.as_str() };
        let kind_s = kind_s.to_string();
        self.requests.insert(id, RequestRecord { id, kind: Kind::Denied(kind_s.clone()), status: Status::Denied, rule: Some(rule.clone()), usd_cents: usd, created_ns: now, agent_pk, payload_hash: hash.clone(), result: None });
        emit("request_denied", json!({"request_id": id, "kind": kind_s, "rule": rule, "usd_cents": usd, "payload_hash": hash}));
        RequestOutcome { request_id: id, status: Status::Denied, rule: Some(rule), signature: None, raw_tx: None, deposit_address: None }
    }

    fn park(&mut self, id: u64, kind: Kind, agent_pk: PublicKey, usd: u64, now: u64, hash: String) {
        let kind_s = match &kind { Kind::Sign(_) => "sign", Kind::Swap(_) => "swap", Kind::Denied(k) => k.as_str() }.to_string();
        self.requests.insert(id, RequestRecord { id, kind, status: Status::Parked, rule: None, usd_cents: usd, created_ns: now, agent_pk, payload_hash: hash.clone(), result: None });
        emit("request_parked", json!({"request_id": id, "kind": kind_s, "usd_cents": usd, "payload_hash": hash}));
    }

    fn mpc_sign(&self, request_id: u64, payload_hash_hex: &str, path: &str) -> Promise {
        let args = json!({"request": {"payload_v2": {"Ecdsa": payload_hash_hex}, "path": path, "domain_id": 0}});
        Promise::new(self.mpc.clone())
            .function_call("sign", args.to_string().into_bytes(), ONE_YOCTO, GAS_MPC_SIGN)
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_SIGN).on_sign(request_id))
    }

    fn fund_swap(&self, request_id: u64, f: &QuoteFacts) -> Promise {
        let token: AccountId = f
            .origin_asset
            .strip_prefix("nep141:")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| env::panic_str("origin asset must be nep141:<account>"));
        let args = json!({"receiver_id": f.deposit_address, "amount": U128(f.amount_in), "memo": f.deposit_memo});
        Promise::new(token)
            .function_call("ft_transfer", args.to_string().into_bytes(), ONE_YOCTO, GAS_FT_TRANSFER)
            .then(Self::ext(env::current_account_id()).with_static_gas(GAS_ON_SWAP).on_swap_funded(request_id, f.deposit_address.clone()))
    }
}

/// Accept both MPC response shapes chainsig.js handles.
fn parse_mpc_signature(v: Value) -> Option<EvmSignature> {
    let big_r = match &v["big_r"] {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.get("affine_point")?.as_str()?.to_string(),
        _ => return None,
    };
    let s = match &v["s"] {
        Value::String(s) => s.clone(),
        Value::Object(o) => o.get("scalar")?.as_str()?.to_string(),
        _ => return None,
    };
    let recovery_id = v["recovery_id"].as_u64()? as u8;
    // big_r is a 33-byte compressed point in hex; r is its x-coordinate
    if big_r.len() != 66 {
        return None;
    }
    Some(EvmSignature { r: big_r[2..].to_ascii_lowercase(), s: s.to_ascii_lowercase(), recovery_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{get_logs, VMContextBuilder};
    use near_sdk::testing_env;
    use policy::{EvmPolicy, IntentsPolicy, Window};

    const S: u64 = 1_000_000_000;
    const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

    fn pk(seed: u8) -> PublicKey {
        let mut b = vec![0u8]; // ed25519 curve prefix
        b.extend(std::iter::repeat(seed).take(32));
        PublicKey::try_from(b).unwrap()
    }

    fn policy() -> Policy {
        Policy {
            version: 1,
            windows: vec![Window { seconds: 3600, max_usd_cents: 5000 }],
            per_request_max_usd_cents: 4000,
            approval_threshold_usd_cents: 3500,
            cooldown_seconds: 0,
            evm: EvmPolicy {
                allowed_chain_ids: vec![84532],
                allowed_recipients: vec!["0xd8da6bf26964af9d7eed9e03e53415d37aa96045".into()],
                allowed_selectors: vec![],
                erc20_tokens: vec![policy::Erc20Token { address: USDC.into(), decimals: 6, usd_cents_per_token: 100 }],
                max_gas_limit: 100_000,
                max_fee_per_gas_wei: 100_000_000_000,
                paths: vec!["treasury-base".into()],
                usd_cents_per_native: 300_000,
            },
            intents: IntentsPolicy {
                allowed_origin_assets: vec!["nep141:usdc.testnet".into()],
                allowed_destination_assets: vec!["nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.stft.near".into()],
                allowed_recipients: vec!["0xcac3C41676deF4FE375E57118f3eB83A99105577".into()],
                max_slippage_bps: 100,
                min_amount_out_ratio_bps: 9800,
                max_quote_age_seconds: 120,
                quote_signer: "ed25519:5J5tkaxyPoR3Q9S8LXfo5bWnXK5Z2bctJ4mB9gENh7co".into(),
            },
        }
    }

    fn ctx(predecessor: &str, signer_pk: PublicKey, now: u64) -> VMContextBuilder {
        let mut c = VMContextBuilder::new();
        c.current_account_id("guardrail.testnet".parse().unwrap())
            .predecessor_account_id(predecessor.parse().unwrap())
            .signer_account_id("guardrail.testnet".parse().unwrap())
            .signer_account_pk(signer_pk)
            .block_timestamp(now)
            .attached_deposit(NearToken::from_yoctonear(0))
            .prepaid_gas(Gas::from_tgas(300));
        c
    }

    fn setup() -> (Guardrail, u64) {
        let now = 1_700_000_000 * S;
        testing_env!(ctx("owner.testnet", pk(9), now).build());
        let mut g = Guardrail::new("owner.testnet".parse().unwrap(), "v1.signer-prod.testnet".parse().unwrap(), policy());
        g.agent_keys.insert(pk(1));
        (g, now)
    }

    fn sign_req(value_eth_milli: u128) -> SignRequest {
        SignRequest {
            chain_id: 84532,
            to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into(),
            value: U128(value_eth_milli * 1_000_000_000_000_000),
            data: None,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: U128(1_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000_000),
            path: "treasury-base".into(),
            intent_note: "pay invoice".into(),
        }
    }

    fn last_event() -> Value {
        let logs = get_logs();
        let l = logs.last().unwrap();
        serde_json::from_str(l.strip_prefix("EVENT_JSON:").unwrap()).unwrap()
    }

    #[test]
    fn agent_key_allow_emits_event_and_promise() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        match g.request_sign(sign_req(5)) {
            PromiseOrValue::Promise(_) => {}
            PromiseOrValue::Value(v) => panic!("expected promise, got {v:?}"),
        }
        let e = last_event();
        assert_eq!(e["event"], "request_allowed");
        assert_eq!(e["data"][0]["usd_cents"], 1506); // 0.005 ETH @ $3000 + 21000 gas * 1 gwei = $0.063
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 1506);
        assert_eq!(g.get_request(1).unwrap().status, Status::Signing);
    }

    #[test]
    fn unknown_key_denied_without_panic() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(2), now).build());
        let PromiseOrValue::Value(o) = g.request_sign(sign_req(1)) else { panic!() };
        assert_eq!(o.status, Status::Denied);
        assert_eq!(o.rule, Some(Rule::AgentKey));
        assert_eq!(last_event()["data"][0]["rule"], "agent_key");
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 0);
    }

    #[test]
    fn external_caller_with_registered_pk_is_still_denied() {
        // key registered, but call did not originate from this account's key
        let (mut g, now) = setup();
        testing_env!(ctx("mallory.testnet", pk(1), now).build());
        let PromiseOrValue::Value(o) = g.request_sign(sign_req(1)) else { panic!() };
        assert_eq!(o.rule, Some(Rule::AgentKey));
    }

    #[test]
    fn bad_recipient_denied_with_rule() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let mut r = sign_req(1);
        r.to = "0x0000000000000000000000000000000000000bad".into();
        let PromiseOrValue::Value(o) = g.request_sign(r) else { panic!() };
        assert_eq!(o.rule, Some(Rule::Recipient));
    }

    fn erc20_req(recipient: &str, amount: u128) -> SignRequest {
        let mut d = hex::decode("a9059cbb").unwrap();
        d.extend([0u8; 12]);
        d.extend(hex::decode(recipient.trim_start_matches("0x")).unwrap());
        d.extend([0u8; 16]);
        d.extend(amount.to_be_bytes());
        let mut r = sign_req(0);
        r.to = USDC.into();
        r.data = Some(near_sdk::json_types::Base64VecU8(d));
        r.gas_limit = 60_000;
        r
    }

    #[test]
    fn erc20_transfer_valued_and_recipient_checked_in_calldata() {
        let (mut g, now) = setup();
        // 12 USDC to an allowed recipient: allowed, valued at $12 + gas
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let PromiseOrValue::Promise(_) = g.request_sign(erc20_req("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", 12_000_000)) else { panic!("expected promise") };
        let e = last_event();
        assert_eq!(e["data"][0]["usd_cents"], 1218); // 1200 + 60000 gas * 1 gwei @ $3000 = 18c
        assert_eq!(e["data"][0]["recipient"], "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 1218);
        // same token, recipient hidden in calldata is not allowlisted
        testing_env!(ctx("guardrail.testnet", pk(1), now + S).build());
        let PromiseOrValue::Value(o) = g.request_sign(erc20_req("0x000000000000000000000000000000000000bad0", 1)) else { panic!() };
        assert_eq!(o.rule, Some(Rule::Recipient));
        // 1,000,000 USDC with value 0 is caught by the per-request cap, not waved through as gas-only
        testing_env!(ctx("guardrail.testnet", pk(1), now + 2 * S).build());
        let PromiseOrValue::Value(o) = g.request_sign(erc20_req("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", 1_000_000_000_000)) else { panic!() };
        assert_eq!(o.rule, Some(Rule::PerRequestCap));
        // unknown token contract
        let mut r = erc20_req("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", 1);
        r.to = "0x0000000000000000000000000000000000000001".into();
        testing_env!(ctx("guardrail.testnet", pk(1), now + 3 * S).build());
        let PromiseOrValue::Value(o) = g.request_sign(r) else { panic!() };
        assert_eq!(o.rule, Some(Rule::Token));
        // malformed transfer calldata
        let mut r = erc20_req("0xd8da6bf26964af9d7eed9e03e53415d37aa96045", 1);
        r.data.as_mut().unwrap().0.push(0);
        testing_env!(ctx("guardrail.testnet", pk(1), now + 4 * S).build());
        let PromiseOrValue::Value(o) = g.request_sign(r) else { panic!() };
        assert_eq!(o.rule, Some(Rule::Malformed));
    }

    #[test]
    fn denied_records_keep_no_payload_and_old_records_are_evicted() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(2), now).build());
        let _ = g.request_sign(sign_req(1));
        assert!(matches!(g.get_request(1).unwrap().kind, Kind::Denied(ref k) if k == "sign"));
        // park request 2 so it survives eviction, then spam denials past the ring size
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let PromiseOrValue::Value(o) = g.request_sign(sign_req(12)) else { panic!() };
        assert_eq!(o.status, Status::Parked);
        // jump the counter so the next two ids are MAX_RECORDS+1 and +2, which evict ids 1 and 2
        g.next_id = MAX_RECORDS + 1;
        for _ in 0..2 {
            testing_env!(ctx("guardrail.testnet", pk(2), now).build());
            let _ = g.request_sign(sign_req(1));
        }
        assert!(g.get_request(1).is_none(), "denied record 1 evicted");
        assert_eq!(g.get_request(2).unwrap().status, Status::Parked, "parked record kept");
        assert!(g.get_request(MAX_RECORDS + 1).is_some());
        assert!(g.get_request(MAX_RECORDS + 2).is_some());
    }

    #[test]
    fn policy_update_keeps_spend_unless_windows_change() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let _ = g.request_sign(sign_req(5));
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 1506);
        testing_env!(ctx("owner.testnet", pk(9), now).build());
        let mut p = policy();
        p.version = 2;
        p.per_request_max_usd_cents = 3000;
        g.set_policy(p);
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 1506, "counters survive a version bump");
        let mut p = policy();
        p.version = 3;
        p.windows = vec![Window { seconds: 7200, max_usd_cents: 5000 }];
        g.set_policy(p);
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 0, "layout change resets");
    }

    #[test]
    fn agent_key_registered_only_after_add_key_succeeds() {
        let (mut g, now) = setup();
        testing_env!(ctx("owner.testnet", pk(9), now).build());
        let _ = g.add_agent_key(pk(3));
        assert!(!g.agent_keys.contains(&pk(3)));
        testing_env!(ctx("guardrail.testnet", pk(9), now).build());
        assert!(!g.on_agent_key_added(pk(3), Err(PromiseError::Failed)));
        assert!(!g.agent_keys.contains(&pk(3)));
        assert!(g.on_agent_key_added(pk(3), Ok(())));
        assert!(g.agent_keys.contains(&pk(3)));
    }

    #[test]
    fn large_request_parks_then_owner_approves() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let PromiseOrValue::Value(o) = g.request_sign(sign_req(12)) else { panic!() }; // $36
        assert_eq!(o.status, Status::Parked);
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 0);
        testing_env!(ctx("owner.testnet", pk(9), now + S).build());
        let PromiseOrValue::Promise(_) = g.approve(1) else { panic!("expected promise") };
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 3606);
        assert_eq!(g.get_request(1).unwrap().status, Status::Signing);
    }

    #[test]
    fn approve_is_owner_only_and_respects_window() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let _ = g.request_sign(sign_req(12)); // parked, $36
        let _ = g.request_sign(sign_req(12)); // parked, $36
        testing_env!(ctx("owner.testnet", pk(9), now).build());
        let _ = g.approve(1);
        let PromiseOrValue::Value(o) = g.approve(2) else { panic!() };
        assert_eq!(o.rule, Some(Rule::WindowCap { index: 0 }));
        assert_eq!(g.get_request(2).unwrap().status, Status::Parked);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn agent_cannot_set_policy() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let mut p = policy();
        p.version = 2;
        g.set_policy(p);
    }

    #[test]
    fn pause_blocks_everything() {
        let (mut g, now) = setup();
        testing_env!(ctx("owner.testnet", pk(9), now).build());
        g.pause();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let PromiseOrValue::Value(o) = g.request_sign(sign_req(1)) else { panic!() };
        assert_eq!(o.rule, Some(Rule::Paused));
    }

    #[test]
    fn sign_failure_refunds_budget() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let _ = g.request_sign(sign_req(5));
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 1506);
        testing_env!(ctx("guardrail.testnet", pk(9), now).build());
        let o = g.on_sign(1, Err(PromiseError::Failed));
        assert_eq!(o.status, Status::SignFailed);
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 0);
    }

    #[test]
    fn sign_success_returns_raw_tx() {
        let (mut g, now) = setup();
        testing_env!(ctx("guardrail.testnet", pk(1), now).build());
        let _ = g.request_sign(sign_req(5));
        testing_env!(ctx("guardrail.testnet", pk(9), now).build());
        let resp = json!({
            "scheme": "Secp256k1",
            "big_r": {"affine_point": "02".to_string() + &"11".repeat(32)},
            "s": {"scalar": "22".repeat(32)},
            "recovery_id": 1
        });
        let o = g.on_sign(1, Ok(resp));
        assert_eq!(o.status, Status::Signed);
        let sig = o.signature.unwrap();
        assert_eq!(sig.r, "11".repeat(32));
        assert_eq!(sig.recovery_id, 1);
        assert!(o.raw_tx.unwrap().starts_with("0x02"));
        assert_eq!(last_event()["event"], "sign_completed");
    }

    #[test]
    fn swap_with_real_staging_quote_is_gated_correctly() {
        // The staging vector's quoteRequest.refundTo is a BTC address, so the
        // refund_to rule must fire — after the signature check passes.
        let (mut g, _) = setup();
        let line = include_str!("../tests/vectors/oneclick_staging.jsonl").lines().next().unwrap();
        let v: Value = serde_json::from_str(line).unwrap();
        let quote: QuoteResponse = serde_json::from_value(v["response"].clone()).unwrap();
        let ts = oneclick::rfc3339_to_ns(&quote.timestamp).unwrap();
        testing_env!(ctx("guardrail.testnet", pk(1), ts + 10 * S).build());
        let PromiseOrValue::Value(o) = g.request_swap(quote.clone()) else { panic!() };
        assert_eq!(o.rule, Some(Rule::RefundTo), "signature verified on the mocked host, refund_to is next");

        // tamper: signature must fail first
        let mut t = quote.clone();
        t.quote.insert("depositAddress".into(), Value::String("bc1qmallory".into()));
        testing_env!(ctx("guardrail.testnet", pk(1), ts + 10 * S).build());
        let PromiseOrValue::Value(o) = g.request_swap(t) else { panic!() };
        assert_eq!(o.rule, Some(Rule::QuoteSignature));

        // stale
        testing_env!(ctx("guardrail.testnet", pk(1), ts + 121 * S).build());
        let PromiseOrValue::Value(o) = g.request_swap(quote) else { panic!() };
        assert_eq!(o.rule, Some(Rule::QuoteAge));
    }

    #[test]
    fn swap_allow_path_funds_deposit_and_consumes_quote() {
        let (mut g, _) = setup();
        let line = include_str!("../tests/vectors/oneclick_staging.jsonl").lines().next().unwrap();
        let v: Value = serde_json::from_str(line).unwrap();
        let mut quote: QuoteResponse = serde_json::from_value(v["response"].clone()).unwrap();
        // Make it pass policy. Changing fields breaks the real signature, so
        // point the policy at a key we control and re-sign on the host.
        quote.quote_request.insert("refundTo".into(), Value::String("guardrail.testnet".into()));
        quote.quote_request.insert("originAsset".into(), Value::String("nep141:usdc.testnet".into()));
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = oneclick::quote_hash_b58(&quote, |b| { use sha2::Digest; sha2::Sha256::digest(b).to_vec() });
        let sig = sk.sign(msg.as_bytes());
        quote.signature = format!("ed25519:{}", bs58::encode(sig.to_bytes()).into_string());
        let mut p = policy();
        p.version = 2;
        p.intents.quote_signer = format!("ed25519:{}", bs58::encode(sk.verifying_key().to_bytes()).into_string());
        let ts = oneclick::rfc3339_to_ns(&quote.timestamp).unwrap();
        testing_env!(ctx("owner.testnet", pk(9), ts).build());
        g.set_policy(p);

        testing_env!(ctx("guardrail.testnet", pk(1), ts + 5 * S).build());
        let PromiseOrValue::Promise(_) = g.request_swap(quote.clone()) else { panic!("expected funding promise") };
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 623);
        let e = last_event();
        assert_eq!(e["event"], "request_allowed");
        assert_eq!(e["data"][0]["deposit_address"], "bc1q873cxltdc560dth6tpwqpehq9uvhxxcdgwnmnw");

        // replay of the same quote
        testing_env!(ctx("guardrail.testnet", pk(1), ts + 6 * S).build());
        let PromiseOrValue::Value(o) = g.request_swap(quote) else { panic!() };
        assert_eq!(o.rule, Some(Rule::QuoteConsumed));

        // funding failure refunds and un-consumes
        testing_env!(ctx("guardrail.testnet", pk(9), ts + 7 * S).build());
        let o = g.on_swap_funded(1, "bc1q873cxltdc560dth6tpwqpehq9uvhxxcdgwnmnw".into(), Err(PromiseError::Failed));
        assert_eq!(o.status, Status::FundFailed);
        assert_eq!(g.get_budget().windows[0].spent_usd_cents, 0);
    }

    #[test]
    fn mpc_signature_parsing_both_shapes() {
        let a = json!({"big_r": {"affine_point": "03".to_string() + &"ab".repeat(32)}, "s": {"scalar": "cd".repeat(32)}, "recovery_id": 0});
        let b = json!({"big_r": "03".to_string() + &"ab".repeat(32), "s": "cd".repeat(32), "recovery_id": 1});
        assert_eq!(parse_mpc_signature(a).unwrap().r, "ab".repeat(32));
        assert_eq!(parse_mpc_signature(b).unwrap().recovery_id, 1);
        assert!(parse_mpc_signature(json!({"big_r": "short"})).is_none());
    }
}
