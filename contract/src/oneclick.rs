//! 1Click quote parsing, canonicalisation and signature verification.
//!
//! Mirrors `quote-signature.ts` of `@defuse-protocol/one-click-sdk-typescript`
//! 0.1.25 byte-for-byte:
//!
//! ```text
//! msg = base58( sha256( stable_stringify({ ...signedRequest, ...signedQuote, timestamp }) ) )
//! ok  = ed25519_verify(signature, utf8(msg), manager_pubkey)
//! ```
//!
//! `stable_stringify` is `json-stable-stringify`: keys sorted, compact, no
//! `undefined`. The merge is *flat*: quote keys overwrite request keys
//! (`deadline` appears in both; the quote's wins).

use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Raw 1Click `QuoteResponse`. `quote_request` and `quote` are kept as maps so
/// new upstream fields never break parsing; we pick the signed subset by name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct QuoteResponse {
    pub timestamp: String,
    pub signature: String,
    pub quote_request: Map<String, Value>,
    pub quote: Map<String, Value>,
}

/// Request fields that are always part of the signed payload (value passed as-is).
const REQ_ALWAYS: &[&str] = &[
    "dry",
    "swapType",
    "slippageTolerance",
    "originAsset",
    "depositType",
    "destinationAsset",
    "amount",
    "refundTo",
    "refundType",
    "recipient",
    "recipientType",
    "deadline",
];
/// Request fields included only when JS-truthy.
const REQ_TRUTHY: &[&str] = &[
    "quoteWaitingTimeMs",
    "referral",
    "virtualChainRecipient",
    "virtualChainRefundRecipient",
    "customRecipientMsg",
];
/// Quote fields always included (dry and non-dry).
const QUOTE_ALWAYS: &[&str] = &[
    "amountIn",
    "amountInFormatted",
    "amountInUsd",
    "minAmountIn",
    "amountOut",
    "amountOutFormatted",
    "amountOutUsd",
    "minAmountOut",
];
/// Extra quote fields for non-dry quotes, included only when JS-truthy.
const QUOTE_NON_DRY_TRUTHY: &[&str] = &[
    "depositAddress",
    "depositMemo",
    "deadline",
    "timeWhenInactive",
    "timeEstimate",
    "refundFee",
    "withdrawFee",
];

/// JavaScript truthiness for the `x ? x : undefined` / `x || undefined` idiom.
fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Build the flat signed object as a BTreeMap so serialisation is key-sorted
/// (near-sdk's serde_json enables `preserve_order`, so `Map` must not be used
/// here). All signed values are scalars, so no nested sorting is needed.
pub fn signed_object(q: &QuoteResponse) -> BTreeMap<String, Value> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for k in REQ_ALWAYS {
        if let Some(v) = q.quote_request.get(*k) {
            out.insert((*k).to_string(), v.clone());
        }
    }
    for k in REQ_TRUTHY {
        if let Some(v) = q.quote_request.get(*k) {
            if js_truthy(v) {
                out.insert((*k).to_string(), v.clone());
            }
        }
    }
    for k in QUOTE_ALWAYS {
        if let Some(v) = q.quote.get(*k) {
            out.insert((*k).to_string(), v.clone());
        }
    }
    let dry = q.quote_request.get("dry").and_then(Value::as_bool).unwrap_or(false);
    if !dry {
        for k in QUOTE_NON_DRY_TRUTHY {
            if let Some(v) = q.quote.get(*k) {
                if js_truthy(v) {
                    out.insert((*k).to_string(), v.clone());
                }
            }
        }
    }
    out.insert("timestamp".to_string(), Value::String(q.timestamp.clone()));
    out
}

/// The exact string the SDK hashes.
pub fn canonical_string(q: &QuoteResponse) -> String {
    near_sdk::serde_json::to_string(&signed_object(q)).expect("serialising a map cannot fail")
}

/// `base58(sha256(canonical))` — the message bytes are the UTF-8 of this string.
pub fn quote_hash_b58(q: &QuoteResponse, sha256: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let canon = canonical_string(q);
    bs58::encode(sha256(canon.as_bytes())).into_string()
}

/// Strip an optional `ed25519:` prefix and base58-decode.
pub fn decode_ed25519(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("ed25519:").unwrap_or(s);
    bs58::decode(s).into_vec().ok()
}

/// Verify with injected primitives so the host (tests) and the wasm runtime
/// (`env::sha256`, `env::ed25519_verify`) share one code path.
pub fn verify_quote(
    q: &QuoteResponse,
    manager_pubkey: &str,
    sha256: impl Fn(&[u8]) -> Vec<u8>,
    ed25519_verify: impl Fn(&[u8; 64], &[u8], &[u8; 32]) -> bool,
) -> bool {
    let Some(sig) = decode_ed25519(&q.signature) else { return false };
    let Some(pk) = decode_ed25519(manager_pubkey) else { return false };
    let (Ok(sig), Ok(pk)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(pk)) else {
        return false;
    };
    let msg = quote_hash_b58(q, sha256);
    ed25519_verify(&sig, msg.as_bytes(), &pk)
}

/// Typed view of the fields the policy needs. Parsing failure => `None`,
/// which the contract maps to `Rule::Malformed`.
#[derive(Clone, Debug)]
pub struct QuoteFacts {
    pub origin_asset: String,
    pub destination_asset: String,
    pub recipient: String,
    pub refund_to: String,
    pub slippage_bps: u64,
    pub amount_in: u128,
    pub amount_in_usd_cents: u64,
    pub amount_out: u128,
    pub min_amount_out: u128,
    pub deposit_address: String,
    pub deposit_memo: Option<String>,
    pub quote_deadline: String,
    pub dry: bool,
}

fn get_str(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k).and_then(Value::as_str).map(str::to_string)
}

fn parse_u128(m: &Map<String, Value>, k: &str) -> Option<u128> {
    match m.get(k)? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// "6.237600000000" -> 623 cents (truncating). Rejects negatives and garbage.
pub fn usd_string_to_cents(s: &str) -> Option<u64> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int: u64 = int.parse().ok()?;
    let mut f = frac.bytes().take(2).map(|b| (b - b'0') as u64);
    let c = f.next().unwrap_or(0) * 10 + f.next().unwrap_or(0);
    int.checked_mul(100)?.checked_add(c)
}

impl QuoteFacts {
    pub fn from_response(q: &QuoteResponse) -> Option<Self> {
        let r = &q.quote_request;
        let qt = &q.quote;
        let dry = r.get("dry").and_then(Value::as_bool).unwrap_or(false);
        Some(Self {
            origin_asset: get_str(r, "originAsset")?,
            destination_asset: get_str(r, "destinationAsset")?,
            recipient: get_str(r, "recipient")?,
            refund_to: get_str(r, "refundTo")?,
            slippage_bps: r.get("slippageTolerance")?.as_u64()?,
            amount_in: parse_u128(qt, "amountIn")?,
            amount_in_usd_cents: usd_string_to_cents(&get_str(qt, "amountInUsd")?)?,
            amount_out: parse_u128(qt, "amountOut")?,
            min_amount_out: parse_u128(qt, "minAmountOut")?,
            deposit_address: if dry { String::new() } else { get_str(qt, "depositAddress")? },
            deposit_memo: get_str(qt, "depositMemo").filter(|s| !s.is_empty()),
            quote_deadline: get_str(qt, "deadline").or_else(|| get_str(r, "deadline"))?,
            dry,
        })
    }
}

/// Parse RFC3339 `YYYY-MM-DDTHH:MM:SS(.fff)Z` to unix nanoseconds. Only the
/// UTC `Z` form 1Click emits; anything else is `None`.
pub fn rfc3339_to_ns(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, u32, u32) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    if d.next().is_some() {
        return None;
    }
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':');
    let (h, mi, se): (u64, u64, u64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    if t.next().is_some() || h > 23 || mi > 59 || se > 60 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // days from civil, Howard Hinnant's algorithm
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp as u64 + 2) / 5 + da as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    if days < 0 {
        return None;
    }
    let secs = days as u64 * 86400 + h * 3600 + mi * 60 + se;
    let mut ns: u64 = 0;
    let mut scale = 100_000_000u64;
    for b in frac.bytes().take(9) {
        ns += (b - b'0') as u64 * scale;
        scale /= 10;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    const STAGING_KEY: &str = "ed25519:5J5tkaxyPoR3Q9S8LXfo5bWnXK5Z2bctJ4mB9gENh7co";

    fn host_sha256(b: &[u8]) -> Vec<u8> {
        Sha256::digest(b).to_vec()
    }
    fn host_ed25519(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> bool {
        VerifyingKey::from_bytes(pk)
            .map(|k| k.verify(msg, &Signature::from_bytes(sig)).is_ok())
            .unwrap_or(false)
    }

    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct Vector {
        name: String,
        canonical: String,
        hash: String,
        valid: bool,
        response: QuoteResponse,
    }

    fn vectors() -> Vec<Vector> {
        include_str!("../tests/vectors/oneclick_staging.jsonl")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| near_sdk::serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn canonical_string_matches_sdk_byte_for_byte() {
        for v in vectors() {
            assert_eq!(canonical_string(&v.response), v.canonical, "{}", v.name);
        }
    }

    #[test]
    fn hash_matches_sdk() {
        for v in vectors() {
            assert_eq!(quote_hash_b58(&v.response, host_sha256), v.hash, "{}", v.name);
        }
    }

    #[test]
    fn real_staging_signatures_verify() {
        for v in vectors() {
            assert!(v.valid);
            assert!(verify_quote(&v.response, STAGING_KEY, host_sha256, host_ed25519), "{}", v.name);
        }
    }

    /// Live production quote (dry, 1 USDC NEAR -> USDC Base) fetched 2026-11-04 from
    /// https://1click.chaindefuser.com/v0/quote, verified against the production manager key.
    #[test]
    fn real_production_signature_verifies() {
        const PROD_KEY: &str = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
        #[derive(Deserialize)]
        #[serde(crate = "near_sdk::serde")]
        struct Prod {
            name: String,
            response: QuoteResponse,
        }
        let mut n = 0;
        for l in include_str!("../tests/vectors/oneclick_production.jsonl").lines().filter(|l| !l.trim().is_empty()) {
            let v: Prod = near_sdk::serde_json::from_str(l).unwrap();
            assert!(verify_quote(&v.response, PROD_KEY, host_sha256, host_ed25519), "{}", v.name);
            assert!(!verify_quote(&v.response, STAGING_KEY, host_sha256, host_ed25519), "{} must not verify under staging", v.name);
            let mut t = v.response.clone();
            t.quote.insert("amountOut".into(), Value::String("1".into()));
            assert!(!verify_quote(&t, PROD_KEY, host_sha256, host_ed25519), "{} tampered", v.name);
            n += 1;
        }
        assert!(n >= 1);
    }

    #[test]
    fn tampered_deposit_address_fails() {
        let mut v = vectors().into_iter().find(|v| v.name == "STAGING_NON_DRY_QUOTE").unwrap();
        v.response.quote.insert("depositAddress".into(), Value::String("bc1q000".into()));
        assert!(!verify_quote(&v.response, STAGING_KEY, host_sha256, host_ed25519));
    }

    #[test]
    fn wrong_key_and_garbage_signature_fail() {
        let v = vectors().remove(0);
        assert!(!verify_quote(&v.response, "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc", host_sha256, host_ed25519));
        let mut bad = v.response.clone();
        bad.signature = "ed25519:111".into();
        assert!(!verify_quote(&bad, STAGING_KEY, host_sha256, host_ed25519));
        bad.signature = "not base58 !!".into();
        assert!(!verify_quote(&bad, STAGING_KEY, host_sha256, host_ed25519));
    }

    #[test]
    fn facts_extract() {
        let v = vectors().into_iter().find(|v| v.name == "STAGING_NON_DRY_QUOTE").unwrap();
        let f = QuoteFacts::from_response(&v.response).unwrap();
        assert_eq!(f.amount_in, 10_000);
        assert_eq!(f.amount_in_usd_cents, 623);
        assert_eq!(f.amount_out, 5_931_560);
        assert_eq!(f.min_amount_out, 5_872_244);
        assert_eq!(f.slippage_bps, 100);
        assert_eq!(f.deposit_address, "bc1q873cxltdc560dth6tpwqpehq9uvhxxcdgwnmnw");
        assert_eq!(f.quote_deadline, "2026-06-26T19:00:00.000Z");
        assert!(!f.dry);
    }

    #[test]
    fn usd_cents() {
        assert_eq!(usd_string_to_cents("6.237600000000"), Some(623));
        assert_eq!(usd_string_to_cents("6"), Some(600));
        assert_eq!(usd_string_to_cents("0.5"), Some(50));
        assert_eq!(usd_string_to_cents("0.009"), Some(0));
        assert_eq!(usd_string_to_cents("-1"), None);
        assert_eq!(usd_string_to_cents("1e3"), None);
        assert_eq!(usd_string_to_cents(""), None);
    }

    #[test]
    fn rfc3339() {
        assert_eq!(rfc3339_to_ns("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_to_ns("2026-06-23T17:10:41.104Z"), Some(1_782_234_641_104_000_000));
        assert_eq!(rfc3339_to_ns("2026-06-23T17:10:41+01:00"), None);
        assert_eq!(rfc3339_to_ns("garbage"), None);
    }
}
