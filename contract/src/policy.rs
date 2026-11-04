//! Policy types and the pure evaluator.
//!
//! Everything here is deterministic and free of host calls so it can be
//! unit-tested exhaustively on the host. The contract (`lib.rs`) supplies
//! `now_ns` and the USD valuation; this module decides.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::near;

pub const BPS: u64 = 10_000;

/// A rolling spend window: at most `max_usd_cents` per `seconds`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub seconds: u64,
    pub max_usd_cents: u64,
}

/// An ERC-20 token the agent may move. `transfer(address,uint256)` calls to
/// `address` are decoded: the decoded recipient must be in
/// `allowed_recipients` and the amount is valued at `usd_cents_per_token`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erc20Token {
    /// Lower-case 0x-prefixed token contract address.
    pub address: String,
    pub decimals: u8,
    /// USD cents per whole token (10^decimals raw units). Static, see spec §5.
    pub usd_cents_per_token: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmPolicy {
    pub allowed_chain_ids: Vec<u64>,
    /// Lower-case 0x-prefixed addresses. Applies to the tx `to` for plain
    /// transfers and arbitrary calls, and to the *decoded* recipient for
    /// ERC-20 `transfer` calls.
    pub allowed_recipients: Vec<String>,
    /// 4-byte selectors as lower-case 0x-prefixed hex for calls other than
    /// ERC-20 `transfer`. Empty `data` is always allowed (plain value
    /// transfer). Empty list means no other calldata allowed. ERC-20
    /// `transfer` is governed by `erc20_tokens`, never by this list.
    pub allowed_selectors: Vec<String>,
    /// Tokens whose `transfer` the agent may call. A `transfer` to a token
    /// not listed here is denied with `Rule::Token`.
    pub erc20_tokens: Vec<Erc20Token>,
    pub max_gas_limit: u64,
    pub max_fee_per_gas_wei: u128,
    /// Derivation path labels the agent may use.
    pub paths: Vec<String>,
    /// Static valuation for caps: USD cents per 1e18 wei of the chain's
    /// native asset. Hackathon simplification; see spec §5.
    pub usd_cents_per_native: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentsPolicy {
    pub allowed_origin_assets: Vec<String>,
    pub allowed_destination_assets: Vec<String>,
    pub allowed_recipients: Vec<String>,
    pub max_slippage_bps: u64,
    /// `minAmountOut * BPS / amountOut` must be >= this.
    pub min_amount_out_ratio_bps: u64,
    pub max_quote_age_seconds: u64,
    /// 1Click manager key, `ed25519:<base58>` or bare base58.
    pub quote_signer: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub version: u32,
    pub windows: Vec<Window>,
    pub per_request_max_usd_cents: u64,
    /// Requests at or above this are parked for owner approval. 0 disables parking.
    pub approval_threshold_usd_cents: u64,
    pub cooldown_seconds: u64,
    pub evm: EvmPolicy,
    pub intents: IntentsPolicy,
}

/// The rule that denied a request. Serialised by name into events.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    Paused,
    AgentKey,
    ChainId,
    /// ERC-20 `transfer` on a token contract not in `erc20_tokens`.
    Token,
    Recipient,
    Selector,
    GasLimit,
    GasPrice,
    Path,
    PerRequestCap,
    Cooldown,
    WindowCap { index: u32 },
    QuoteSignature,
    QuoteAge,
    QuoteDeadline,
    QuoteConsumed,
    RefundTo,
    OriginAsset,
    DestinationAsset,
    Slippage,
    MinAmountOutRatio,
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Park,
    Deny(Rule),
}

/// Live counters. One entry per policy window, same order.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetState {
    pub windows: Vec<WindowState>,
    pub last_request_ns: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowState {
    pub start_ns: u64,
    pub spent_usd_cents: u64,
}

impl BudgetState {
    pub fn for_policy(policy: &Policy, now_ns: u64) -> Self {
        Self {
            windows: policy
                .windows
                .iter()
                .map(|_| WindowState { start_ns: now_ns, spent_usd_cents: 0 })
                .collect(),
            last_request_ns: 0,
        }
    }

    /// Reset any window whose period has elapsed. Idempotent.
    pub fn roll(&mut self, policy: &Policy, now_ns: u64) {
        if self.windows.len() != policy.windows.len() {
            *self = Self::for_policy(policy, now_ns);
            return;
        }
        for (w, cfg) in self.windows.iter_mut().zip(&policy.windows) {
            if now_ns.saturating_sub(w.start_ns) >= cfg.seconds * 1_000_000_000 {
                w.start_ns = now_ns;
                w.spent_usd_cents = 0;
            }
        }
    }

    /// Record an allowed spend. Call only after `Decision::Allow`.
    pub fn commit(&mut self, now_ns: u64, usd_cents: u64) {
        for w in &mut self.windows {
            w.spent_usd_cents = w.spent_usd_cents.saturating_add(usd_cents);
        }
        self.last_request_ns = now_ns;
    }

    /// Undo a committed spend after a downstream failure.
    pub fn refund(&mut self, usd_cents: u64) {
        for w in &mut self.windows {
            w.spent_usd_cents = w.spent_usd_cents.saturating_sub(usd_cents);
        }
    }
}

/// Decoded ERC-20 `transfer(address,uint256)` as the policy sees it.
#[derive(Clone, Debug)]
pub struct Erc20Facts<'a> {
    /// token contract (the tx `to`)
    pub token: &'a str,
    /// decoded recipient
    pub recipient: &'a str,
}

/// Fields of an EVM sign request the policy looks at. Already normalised
/// (lower-case hex) by the caller. `usd_cents` must already include the
/// ERC-20 amount valued with [`erc20_usd_cents`] when `erc20` is set.
#[derive(Clone, Debug)]
pub struct EvmFacts<'a> {
    pub chain_id: u64,
    pub to: &'a str,
    pub selector: Option<&'a str>,
    pub erc20: Option<Erc20Facts<'a>>,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub path: &'a str,
    pub usd_cents: u64,
}

/// Fields of a 1Click quote the policy looks at, after signature checks.
#[derive(Clone, Debug)]
pub struct SwapFacts<'a> {
    pub signature_ok: bool,
    pub already_consumed: bool,
    pub quote_timestamp_ns: u64,
    pub quote_deadline_ns: u64,
    pub refund_to: &'a str,
    pub self_account: &'a str,
    pub origin_asset: &'a str,
    pub destination_asset: &'a str,
    pub recipient: &'a str,
    pub slippage_bps: u64,
    pub amount_out: u128,
    pub min_amount_out: u128,
    pub usd_cents: u64,
}

/// Value `amount` raw units of `token` in USD cents using the policy's
/// static table. `None` when the token is not listed.
pub fn erc20_usd_cents(policy: &Policy, token: &str, amount: u128) -> Option<u64> {
    let t = policy.evm.erc20_tokens.iter().find(|t| t.address == token)?;
    let unit = 10u128.checked_pow(t.decimals as u32)?;
    let v = amount.saturating_mul(t.usd_cents_per_token as u128) / unit;
    Some(v.min(u64::MAX as u128) as u64)
}

fn budget_rules(
    policy: &Policy,
    state: &BudgetState,
    now_ns: u64,
    usd_cents: u64,
) -> Result<(), Rule> {
    if policy.per_request_max_usd_cents > 0 && usd_cents > policy.per_request_max_usd_cents {
        return Err(Rule::PerRequestCap);
    }
    if policy.cooldown_seconds > 0
        && state.last_request_ns > 0
        && now_ns.saturating_sub(state.last_request_ns) < policy.cooldown_seconds * 1_000_000_000
    {
        return Err(Rule::Cooldown);
    }
    for (i, (w, cfg)) in state.windows.iter().zip(&policy.windows).enumerate() {
        if w.spent_usd_cents.saturating_add(usd_cents) > cfg.max_usd_cents {
            return Err(Rule::WindowCap { index: i as u32 });
        }
    }
    Ok(())
}

/// Budget-only re-check used when an owner approves a parked request: the
/// non-budget rules were already evaluated when it was parked.
pub fn evaluate_budget_only(policy: &Policy, state: &BudgetState, now_ns: u64, paused: bool, usd_cents: u64) -> Decision {
    if paused {
        return Decision::Deny(Rule::Paused);
    }
    match budget_rules(policy, state, now_ns, usd_cents) {
        Err(r) => Decision::Deny(r),
        Ok(()) => Decision::Allow,
    }
}

fn park_or_allow(policy: &Policy, usd_cents: u64) -> Decision {
    if policy.approval_threshold_usd_cents > 0 && usd_cents >= policy.approval_threshold_usd_cents {
        Decision::Park
    } else {
        Decision::Allow
    }
}

/// Evaluate an EVM sign request. `state` must already be rolled to `now_ns`.
/// `paused` and the agent-key check are passed in because they live in the
/// contract, not the policy.
pub fn evaluate_sign(
    policy: &Policy,
    state: &BudgetState,
    now_ns: u64,
    paused: bool,
    agent_key_ok: bool,
    f: &EvmFacts,
) -> Decision {
    if paused {
        return Decision::Deny(Rule::Paused);
    }
    if !agent_key_ok {
        return Decision::Deny(Rule::AgentKey);
    }
    if !policy.evm.allowed_chain_ids.contains(&f.chain_id) {
        return Decision::Deny(Rule::ChainId);
    }
    match &f.erc20 {
        Some(t) => {
            if !policy.evm.erc20_tokens.iter().any(|k| k.address == t.token) {
                return Decision::Deny(Rule::Token);
            }
            if !policy.evm.allowed_recipients.iter().any(|a| a == t.recipient) {
                return Decision::Deny(Rule::Recipient);
            }
        }
        None => {
            if !policy.evm.allowed_recipients.iter().any(|a| a == f.to) {
                return Decision::Deny(Rule::Recipient);
            }
            if let Some(sel) = f.selector {
                if !policy.evm.allowed_selectors.iter().any(|s| s == sel) {
                    return Decision::Deny(Rule::Selector);
                }
            }
        }
    }
    if f.gas_limit > policy.evm.max_gas_limit {
        return Decision::Deny(Rule::GasLimit);
    }
    if f.max_fee_per_gas > policy.evm.max_fee_per_gas_wei {
        return Decision::Deny(Rule::GasPrice);
    }
    if !policy.evm.paths.iter().any(|p| p == f.path) {
        return Decision::Deny(Rule::Path);
    }
    if let Err(r) = budget_rules(policy, state, now_ns, f.usd_cents) {
        return Decision::Deny(r);
    }
    park_or_allow(policy, f.usd_cents)
}

/// Evaluate a 1Click swap request. `state` must already be rolled to `now_ns`.
pub fn evaluate_swap(
    policy: &Policy,
    state: &BudgetState,
    now_ns: u64,
    paused: bool,
    agent_key_ok: bool,
    f: &SwapFacts,
) -> Decision {
    if paused {
        return Decision::Deny(Rule::Paused);
    }
    if !agent_key_ok {
        return Decision::Deny(Rule::AgentKey);
    }
    if !f.signature_ok {
        return Decision::Deny(Rule::QuoteSignature);
    }
    if f.already_consumed {
        return Decision::Deny(Rule::QuoteConsumed);
    }
    let max_age = policy.intents.max_quote_age_seconds * 1_000_000_000;
    if f.quote_timestamp_ns > now_ns || now_ns - f.quote_timestamp_ns > max_age {
        return Decision::Deny(Rule::QuoteAge);
    }
    if f.quote_deadline_ns <= now_ns {
        return Decision::Deny(Rule::QuoteDeadline);
    }
    if f.refund_to != f.self_account {
        return Decision::Deny(Rule::RefundTo);
    }
    if !policy.intents.allowed_origin_assets.iter().any(|a| a == f.origin_asset) {
        return Decision::Deny(Rule::OriginAsset);
    }
    if !policy.intents.allowed_destination_assets.iter().any(|a| a == f.destination_asset) {
        return Decision::Deny(Rule::DestinationAsset);
    }
    if !policy.intents.allowed_recipients.iter().any(|a| a == f.recipient) {
        return Decision::Deny(Rule::Recipient);
    }
    if f.slippage_bps > policy.intents.max_slippage_bps {
        return Decision::Deny(Rule::Slippage);
    }
    if f.amount_out == 0 {
        return Decision::Deny(Rule::Malformed);
    }
    let ratio = f.min_amount_out.saturating_mul(BPS as u128) / f.amount_out;
    if ratio < policy.intents.min_amount_out_ratio_bps as u128 {
        return Decision::Deny(Rule::MinAmountOutRatio);
    }
    if let Err(r) = budget_rules(policy, state, now_ns, f.usd_cents) {
        return Decision::Deny(r);
    }
    park_or_allow(policy, f.usd_cents)
}

// Compile-time check that the policy types stay borsh-serialisable.
#[allow(dead_code)]
fn _assert_borsh<T: BorshSerialize + BorshDeserialize>() {}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn policy() -> Policy {
        Policy {
            version: 1,
            windows: vec![
                Window { seconds: 3600, max_usd_cents: 5000 },
                Window { seconds: 86400, max_usd_cents: 25000 },
            ],
            per_request_max_usd_cents: 2000,
            approval_threshold_usd_cents: 1000,
            cooldown_seconds: 60,
            evm: EvmPolicy {
                allowed_chain_ids: vec![84532],
                allowed_recipients: vec!["0xaaaa".into()],
                allowed_selectors: vec!["0x095ea7b3".into()],
                erc20_tokens: vec![Erc20Token { address: "0xusdc".into(), decimals: 6, usd_cents_per_token: 100 }],
                max_gas_limit: 300_000,
                max_fee_per_gas_wei: 50_000_000_000,
                paths: vec!["treasury-base".into()],
                usd_cents_per_native: 300_000,
            },
            intents: IntentsPolicy {
                allowed_origin_assets: vec!["nep141:usdc.near".into()],
                allowed_destination_assets: vec!["nep141:eth.omft.near".into()],
                allowed_recipients: vec!["0xbbbb".into()],
                max_slippage_bps: 100,
                min_amount_out_ratio_bps: 9800,
                max_quote_age_seconds: 120,
                quote_signer: "ed25519:x".into(),
            },
        }
    }

    fn evm(usd: u64) -> EvmFacts<'static> {
        EvmFacts {
            chain_id: 84532,
            to: "0xaaaa",
            selector: None,
            erc20: None,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            path: "treasury-base",
            usd_cents: usd,
        }
    }

    fn swap(now: u64, usd: u64) -> SwapFacts<'static> {
        SwapFacts {
            signature_ok: true,
            already_consumed: false,
            quote_timestamp_ns: now - 10 * S,
            quote_deadline_ns: now + 600 * S,
            refund_to: "guardrail.testnet",
            self_account: "guardrail.testnet",
            origin_asset: "nep141:usdc.near",
            destination_asset: "nep141:eth.omft.near",
            recipient: "0xbbbb",
            slippage_bps: 100,
            amount_out: 1_000_000,
            min_amount_out: 990_000,
            usd_cents: usd,
        }
    }

    fn fresh() -> (Policy, BudgetState, u64) {
        let p = policy();
        let now = 1_700_000_000 * S;
        let st = BudgetState::for_policy(&p, now);
        (p, st, now)
    }

    #[test]
    fn sign_allow_and_park() {
        let (p, st, now) = fresh();
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &evm(500)), Decision::Allow);
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &evm(1000)), Decision::Park);
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &evm(1999)), Decision::Park);
    }

    #[test]
    fn sign_deny_rules_in_order() {
        let (p, st, now) = fresh();
        let d = |paused, key, f: EvmFacts| evaluate_sign(&p, &st, now, paused, key, &f);
        assert_eq!(d(true, true, evm(1)), Decision::Deny(Rule::Paused));
        assert_eq!(d(false, false, evm(1)), Decision::Deny(Rule::AgentKey));
        assert_eq!(d(false, true, EvmFacts { chain_id: 1, ..evm(1) }), Decision::Deny(Rule::ChainId));
        assert_eq!(d(false, true, EvmFacts { to: "0xbad", ..evm(1) }), Decision::Deny(Rule::Recipient));
        assert_eq!(d(false, true, EvmFacts { selector: Some("0xdeadbeef"), ..evm(1) }), Decision::Deny(Rule::Selector));
        assert_eq!(d(false, true, EvmFacts { selector: Some("0x095ea7b3"), ..evm(1) }), Decision::Allow);
        assert_eq!(d(false, true, EvmFacts { gas_limit: 300_001, ..evm(1) }), Decision::Deny(Rule::GasLimit));
        assert_eq!(d(false, true, EvmFacts { max_fee_per_gas: 50_000_000_001, ..evm(1) }), Decision::Deny(Rule::GasPrice));
        assert_eq!(d(false, true, EvmFacts { path: "other", ..evm(1) }), Decision::Deny(Rule::Path));
        assert_eq!(d(false, true, evm(2001)), Decision::Deny(Rule::PerRequestCap));
        assert_eq!(d(false, true, evm(2000)), Decision::Park);
    }

    #[test]
    fn erc20_transfer_checks_token_and_decoded_recipient() {
        let (p, st, now) = fresh();
        let d = |f: EvmFacts| evaluate_sign(&p, &st, now, false, true, &f);
        let sel = Some("0xa9059cbb");
        // token contract is the tx `to`; it is NOT in allowed_recipients and must not need to be
        let ok = EvmFacts { to: "0xusdc", selector: sel, erc20: Some(Erc20Facts { token: "0xusdc", recipient: "0xaaaa" }), ..evm(1) };
        assert_eq!(d(ok.clone()), Decision::Allow);
        // unknown token
        assert_eq!(
            d(EvmFacts { to: "0xunkn", erc20: Some(Erc20Facts { token: "0xunkn", recipient: "0xaaaa" }), ..ok.clone() }),
            Decision::Deny(Rule::Token)
        );
        // allowed token, recipient hidden in calldata is not allowlisted
        assert_eq!(
            d(EvmFacts { erc20: Some(Erc20Facts { token: "0xusdc", recipient: "0xbad" }), ..ok.clone() }),
            Decision::Deny(Rule::Recipient)
        );
        // allowed_selectors does not open the transfer path: an allowed recipient as `to`
        // with a transfer selector but no decoded facts is a caller bug, still gated by selector list
        assert_eq!(d(EvmFacts { to: "0xaaaa", selector: sel, erc20: None, ..evm(1) }), Decision::Deny(Rule::Selector));
    }

    #[test]
    fn erc20_valuation() {
        let p = policy();
        assert_eq!(erc20_usd_cents(&p, "0xusdc", 1_500_000), Some(150));
        assert_eq!(erc20_usd_cents(&p, "0xusdc", 999_999), Some(99));
        assert_eq!(erc20_usd_cents(&p, "0xnope", 1), None);
        // valued amount then hits caps: 25 USDC + gas with per-request cap $20
        let (p, st, now) = fresh();
        let usd = erc20_usd_cents(&p, "0xusdc", 25_000_000).unwrap();
        let f = EvmFacts { to: "0xusdc", selector: Some("0xa9059cbb"), erc20: Some(Erc20Facts { token: "0xusdc", recipient: "0xaaaa" }), usd_cents: usd, ..evm(0) };
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &f), Decision::Deny(Rule::PerRequestCap));
    }

    #[test]
    fn cooldown_then_window_caps() {
        let (p, mut st, now) = fresh();
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &evm(500)), Decision::Allow);
        st.commit(now, 500);
        // 59s later: cooldown
        assert_eq!(evaluate_sign(&p, &st, now + 59 * S, false, true, &evm(1)), Decision::Deny(Rule::Cooldown));
        // 60s later: ok
        assert_eq!(evaluate_sign(&p, &st, now + 60 * S, false, true, &evm(1)), Decision::Allow);
        // fill the hourly window: 500 spent, cap 5000, request 4501 -> per-request cap first
        assert_eq!(evaluate_sign(&p, &st, now + 60 * S, false, true, &evm(4501)), Decision::Deny(Rule::PerRequestCap));
        // 1999 x2 then window
        st.commit(now + 60 * S, 1999);
        st.commit(now + 120 * S, 1999);
        // spent 4498; 503 would exceed 5000
        assert_eq!(evaluate_sign(&p, &st, now + 180 * S, false, true, &evm(503)), Decision::Deny(Rule::WindowCap { index: 0 }));
        assert_eq!(evaluate_sign(&p, &st, now + 180 * S, false, true, &evm(502)), Decision::Allow);
    }

    #[test]
    fn window_rollover_resets_only_elapsed_windows() {
        let (p, mut st, now) = fresh();
        st.commit(now, 4000);
        let later = now + 3600 * S;
        st.roll(&p, later);
        assert_eq!(st.windows[0].spent_usd_cents, 0);
        assert_eq!(st.windows[0].start_ns, later);
        assert_eq!(st.windows[1].spent_usd_cents, 4000);
        assert_eq!(st.windows[1].start_ns, now);
        // daily cap: 4000 + 1999 ok, then 25000 boundary
        st.commit(later, 1999);
        let st2 = st.clone();
        let mut s = st2;
        for _ in 0..9 {
            s.commit(later, 1999);
        }
        // daily spent 4000 + 10*1999 = 23990; hourly would also be over, so
        // simulate the hourly window having rolled and check the daily cap fires
        let t = later + 3600 * S;
        s.windows[0] = WindowState { start_ns: t, spent_usd_cents: 0 };
        assert_eq!(
            evaluate_sign(&p, &s, t, false, true, &evm(1011)),
            Decision::Deny(Rule::WindowCap { index: 1 })
        );
        assert_eq!(evaluate_sign(&p, &s, t, false, true, &evm(1010)), Decision::Park);
    }

    #[test]
    fn refund_undoes_commit() {
        let (p, mut st, now) = fresh();
        st.commit(now, 1500);
        st.refund(1500);
        assert_eq!(st.windows[0].spent_usd_cents, 0);
        assert_eq!(evaluate_sign(&p, &st, now + 61 * S, false, true, &evm(1999)), Decision::Park);
    }

    #[test]
    fn swap_allow_and_deny_rules() {
        let (p, st, now) = fresh();
        let d = |f: SwapFacts| evaluate_swap(&p, &st, now, false, true, &f);
        assert_eq!(d(swap(now, 500)), Decision::Allow);
        assert_eq!(d(SwapFacts { signature_ok: false, ..swap(now, 1) }), Decision::Deny(Rule::QuoteSignature));
        assert_eq!(d(SwapFacts { already_consumed: true, ..swap(now, 1) }), Decision::Deny(Rule::QuoteConsumed));
        assert_eq!(d(SwapFacts { quote_timestamp_ns: now - 121 * S, ..swap(now, 1) }), Decision::Deny(Rule::QuoteAge));
        assert_eq!(d(SwapFacts { quote_timestamp_ns: now + 1, ..swap(now, 1) }), Decision::Deny(Rule::QuoteAge));
        assert_eq!(d(SwapFacts { quote_deadline_ns: now, ..swap(now, 1) }), Decision::Deny(Rule::QuoteDeadline));
        assert_eq!(d(SwapFacts { refund_to: "agent.testnet", ..swap(now, 1) }), Decision::Deny(Rule::RefundTo));
        assert_eq!(d(SwapFacts { origin_asset: "nep141:x", ..swap(now, 1) }), Decision::Deny(Rule::OriginAsset));
        assert_eq!(d(SwapFacts { destination_asset: "nep141:x", ..swap(now, 1) }), Decision::Deny(Rule::DestinationAsset));
        assert_eq!(d(SwapFacts { recipient: "0xbad", ..swap(now, 1) }), Decision::Deny(Rule::Recipient));
        assert_eq!(d(SwapFacts { slippage_bps: 101, ..swap(now, 1) }), Decision::Deny(Rule::Slippage));
        assert_eq!(d(SwapFacts { min_amount_out: 979_999, ..swap(now, 1) }), Decision::Deny(Rule::MinAmountOutRatio));
        assert_eq!(d(SwapFacts { min_amount_out: 980_000, ..swap(now, 1) }), Decision::Allow);
        assert_eq!(d(SwapFacts { amount_out: 0, ..swap(now, 1) }), Decision::Deny(Rule::Malformed));
        assert_eq!(d(swap(now, 2001)), Decision::Deny(Rule::PerRequestCap));
        assert_eq!(d(swap(now, 1000)), Decision::Park);
    }

    #[test]
    fn zero_threshold_disables_parking() {
        let (mut p, st, now) = fresh();
        p.approval_threshold_usd_cents = 0;
        assert_eq!(evaluate_sign(&p, &st, now, false, true, &evm(2000)), Decision::Allow);
    }

    #[test]
    fn rule_serialises_snake_case_with_index() {
        let j = serde_json::to_string(&Rule::WindowCap { index: 1 }).unwrap();
        assert_eq!(j, r#"{"window_cap":{"index":1}}"#);
        assert_eq!(serde_json::to_string(&Rule::PerRequestCap).unwrap(), r#""per_request_cap""#);
    }
}
