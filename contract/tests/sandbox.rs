//! near-workspaces sandbox tests: guardrail + mock `v1.signer` + mock NEP-141.
//!
//! Run with `cargo test -p guardrail --test sandbox -- --nocapture` to see gas.
//! The wasm artefacts are built on demand by [`build_wasm`].

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

const WASM_DIR: &str = "target/wasm32-unknown-unknown/release";
static BUILD: Once = Once::new();

fn build_wasm() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    BUILD.call_once(|| {
        let st = Command::new("cargo")
            .args(["build", "-p", "guardrail", "-p", "mock-signer", "-p", "mock-ft", "--target", "wasm32-unknown-unknown", "--release"])
            .current_dir(&root)
            .status()
            .expect("cargo build");
        assert!(st.success(), "wasm build failed");
    });
    let read = |n: &str| std::fs::read(root.join(WASM_DIR).join(n)).map_err(|e| anyhow!("{n}: {e}"));
    Ok((read("guardrail.wasm")?, read("mock_signer.wasm")?, read("mock_ft.wasm")?))
}

/// One deployed world: owner account, guardrail, mock signer, mock ft, and an
/// agent that signs with a function-call key living on the guardrail account.
struct World {
    worker: Worker<near_workspaces::network::Sandbox>,
    owner: Account,
    guardrail: Contract,
    signer: Contract,
    ft: Contract,
    agent: Account,
    agent_pk: String,
    quote_sk: SigningKey,
}

const RECIPIENT: &str = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

fn policy(ft: &str, quote_signer: &str) -> Value {
    json!({
        "version": 1,
        "windows": [{ "seconds": 3600, "max_usd_cents": 5000 }],
        "per_request_max_usd_cents": 4000,
        "approval_threshold_usd_cents": 3500,
        "cooldown_seconds": 0,
        "evm": {
            "allowed_chain_ids": [84532],
            "allowed_recipients": [RECIPIENT],
            "allowed_selectors": [],
            "erc20_tokens": [{ "address": USDC, "decimals": 6, "usd_cents_per_token": 100 }],
            "max_gas_limit": 100000,
            "max_fee_per_gas_wei": 100000000000u64,
            "paths": ["treasury-base"],
            "usd_cents_per_native": 300000
        },
        "intents": {
            "allowed_origin_assets": [format!("nep141:{ft}")],
            "allowed_destination_assets": ["nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.stft.near"],
            "allowed_recipients": ["0xcac3C41676deF4FE375E57118f3eB83A99105577"],
            "max_slippage_bps": 100,
            "min_amount_out_ratio_bps": 9800,
            "max_quote_age_seconds": 120,
            "quote_signer": quote_signer
        }
    })
}

async fn world() -> Result<World> {
    let (gw, sw, fw) = build_wasm()?;
    let worker = near_workspaces::sandbox().await?;
    let owner = worker.dev_create_account().await?;
    let signer = worker.dev_deploy(&sw).await?;
    let ft = worker.dev_deploy(&fw).await?;
    let r = ft.call("new").transact().await?;
    assert!(r.is_success(), "ft new: {:?}", r.failures());
    let guardrail = worker.dev_deploy(&gw).await?;

    let quote_sk = SigningKey::from_bytes(&[7u8; 32]);
    let quote_pk = format!("ed25519:{}", bs58::encode(quote_sk.verifying_key().to_bytes()).into_string());
    let r = guardrail
        .call("new")
        .args_json(json!({ "owner": owner.id(), "mpc": signer.id(), "policy": policy(ft.id().as_str(), &quote_pk) }))
        .transact()
        .await?;
    assert!(r.is_success(), "guardrail new: {:?}", r.failures());

    // agent key: owner registers it, AddKey happens on the guardrail account
    let sk = SecretKey::from_random(KeyType::ED25519);
    let agent_pk = sk.public_key().to_string();
    let r = owner
        .call(guardrail.id(), "add_agent_key")
        .args_json(json!({ "public_key": agent_pk }))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.failures());
    assert_eq!(r.json::<bool>()?, true, "key registered in callback");
    let agent = Account::from_secret_key(guardrail.id().clone(), sk, &worker);

    // treasury: 100 USDC-mock
    let r = ft.call("mint").args_json(json!({ "account_id": guardrail.id(), "amount": "100000000" })).transact().await?;
    assert!(r.is_success(), "mint: {:?}", r.failures());

    Ok(World { worker, owner, guardrail, signer, ft, agent, agent_pk, quote_sk })
}

fn sign_req(value_eth_milli: u64) -> Value {
    json!({
        "chain_id": 84532,
        "to": RECIPIENT,
        "value": (value_eth_milli as u128 * 1_000_000_000_000_000).to_string(),
        "data": null,
        "nonce": 0,
        "gas_limit": 21000,
        "max_fee_per_gas": "1000000000",
        "max_priority_fee_per_gas": "1000000000",
        "path": "treasury-base",
        "intent_note": "sandbox"
    })
}

/// Parse the return value without consuming the result (so logs/gas stay readable).
fn out(r: &ExecutionFinalResult) -> Value {
    r.clone().json::<Value>().unwrap_or(Value::Null)
}

fn events(r: &ExecutionFinalResult) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str(j).unwrap())
        .collect()
}

fn event_names(r: &ExecutionFinalResult) -> Vec<String> {
    events(r).iter().map(|e| e["event"].as_str().unwrap().to_string()).collect()
}

impl World {
    async fn agent_call(&self, method: &str, args: Value) -> Result<ExecutionFinalResult> {
        Ok(self.agent.call(self.guardrail.id(), method).args_json(args).gas(Gas::from_tgas(300)).transact().await?)
    }
    async fn spent(&self) -> Result<u64> {
        let b: Value = self.guardrail.view("get_budget").await?.json()?;
        Ok(b["windows"][0]["spent_usd_cents"].as_u64().unwrap())
    }
    async fn ft_balance(&self, id: &str) -> Result<u128> {
        let v: String = self.ft.view("ft_balance_of").args_json(json!({ "account_id": id })).await?.json()?;
        Ok(v.parse()?)
    }
    /// A non-dry 1Click-shaped quote signed with the sandbox manager key.
    fn quote(&self, deposit_address: &str, amount_in: u128) -> Value {
        let now = chrono::Utc::now();
        let ts = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let deadline = (now + chrono::Duration::minutes(10)).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let request = json!({
            "dry": false, "swapType": "EXACT_INPUT", "slippageTolerance": 100,
            "originAsset": format!("nep141:{}", self.ft.id()), "depositType": "ORIGIN_CHAIN",
            "destinationAsset": "nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.stft.near",
            "amount": amount_in.to_string(), "refundTo": self.guardrail.id().as_str(), "refundType": "ORIGIN_CHAIN",
            "recipient": "0xcac3C41676deF4FE375E57118f3eB83A99105577", "recipientType": "DESTINATION_CHAIN",
            "deadline": deadline
        });
        let usd = format!("{}.000000000000", amount_in / 1_000_000);
        let quote = json!({
            "amountIn": amount_in.to_string(), "amountInFormatted": "x", "amountInUsd": usd, "minAmountIn": amount_in.to_string(),
            "amountOut": "1000000", "amountOutFormatted": "1", "amountOutUsd": usd, "minAmountOut": "990000",
            "depositAddress": deposit_address, "deadline": deadline, "timeWhenInactive": deadline, "timeEstimate": 10
        });
        // canonical = stable-stringify(flat merge + timestamp)
        let mut flat: BTreeMap<String, Value> = BTreeMap::new();
        for (k, v) in request.as_object().unwrap() {
            flat.insert(k.clone(), v.clone());
        }
        for (k, v) in quote.as_object().unwrap() {
            flat.insert(k.clone(), v.clone());
        }
        flat.insert("timestamp".into(), Value::String(ts.clone()));
        let canon = serde_json::to_string(&flat).unwrap();
        let msg = bs58::encode(Sha256::digest(canon.as_bytes())).into_string();
        let sig = self.quote_sk.sign(msg.as_bytes());
        json!({
            "timestamp": ts,
            "signature": format!("ed25519:{}", bs58::encode(sig.to_bytes()).into_string()),
            "quoteRequest": request,
            "quote": quote
        })
    }
}

#[tokio::test]
async fn sign_allow_end_to_end() -> Result<()> {
    let w = world().await?;
    let r = w.agent_call("request_sign", json!({ "req": sign_req(5) })).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "signed");
    assert_eq!(o["signature"]["r"], "11".repeat(32));
    assert!(o["raw_tx"].as_str().unwrap().starts_with("0x02"));
    assert_eq!(event_names(&r), ["request_allowed", "sign_completed"]);
    assert_eq!(w.spent().await?, 1506);
    let rec: Value = w.guardrail.view("get_request").args_json(json!({ "request_id": 1 })).await?.json()?;
    assert_eq!(rec["status"], "signed");
    let calls: u64 = w.signer.view("calls").await?.json()?;
    assert_eq!(calls, 1);
    println!("GAS request_sign allow->signed: {} TGas", r.total_gas_burnt.as_tgas());
    Ok(())
}

#[tokio::test]
async fn deny_emits_event_and_leaves_budget() -> Result<()> {
    let w = world().await?;
    let mut req = sign_req(1);
    req["to"] = json!("0x0000000000000000000000000000000000000bad");
    let r = w.agent_call("request_sign", json!({ "req": req })).await?;
    assert!(r.is_success(), "denial must not panic: {:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "denied");
    assert_eq!(o["rule"], "recipient");
    let ev = events(&r);
    assert_eq!(ev[0]["event"], "request_denied");
    assert_eq!(ev[0]["data"][0]["rule"], "recipient");
    assert_eq!(w.spent().await?, 0);
    let calls: u64 = w.signer.view("calls").await?.json()?;
    assert_eq!(calls, 0);
    println!("GAS request_sign deny: {} TGas", r.total_gas_burnt.as_tgas());
    Ok(())
}

#[tokio::test]
async fn erc20_hidden_recipient_denied_and_allowed_one_priced() -> Result<()> {
    let w = world().await?;
    let calldata = |recipient: &str, amount: u128| {
        let mut d = hex::decode("a9059cbb").unwrap();
        d.extend([0u8; 12]);
        d.extend(hex::decode(recipient.trim_start_matches("0x")).unwrap());
        d.extend([0u8; 16]);
        d.extend(amount.to_be_bytes());
        near_sdk_base64(&d)
    };
    let mut req = sign_req(0);
    req["to"] = json!(USDC);
    req["gas_limit"] = json!(60000);
    req["data"] = json!(calldata("0x000000000000000000000000000000000000bad0", 1));
    let r = w.agent_call("request_sign", json!({ "req": req.clone() })).await?;
    let o = out(&r);
    assert_eq!(o["rule"], "recipient", "recipient hidden in calldata is checked");
    req["data"] = json!(calldata(RECIPIENT, 12_000_000));
    let r = w.agent_call("request_sign", json!({ "req": req })).await?;
    let o = out(&r);
    assert_eq!(o["status"], "signed", "{o}");
    assert_eq!(w.spent().await?, 1218, "12 USDC + gas priced into the window");
    Ok(())
}

fn near_sdk_base64(b: &[u8]) -> String {
    // minimal base64 (standard alphabet, padded) to avoid another dev-dep
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[tokio::test]
async fn park_then_owner_approves() -> Result<()> {
    let w = world().await?;
    let r = w.agent_call("request_sign", json!({ "req": sign_req(12) })).await?; // $36 >= $35 threshold
    let o = out(&r);
    assert_eq!(o["status"], "parked");
    assert_eq!(w.spent().await?, 0);
    // agent cannot approve
    // rejected by the RPC before execution (FC key not allowed to call `approve`)
    match w.agent_call("approve", json!({ "request_id": 1 })).await {
        Ok(r) => assert!(r.is_failure(), "FC key is restricted to request_sign,request_swap"),
        Err(_) => {}
    }
    let r = w.owner.call(w.guardrail.id(), "approve").args_json(json!({ "request_id": 1 })).gas(Gas::from_tgas(300)).transact().await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "signed");
    assert_eq!(event_names(&r), ["request_approved", "sign_completed"]);
    assert_eq!(w.spent().await?, 3606);
    Ok(())
}

#[tokio::test]
async fn sign_failure_refunds_budget() -> Result<()> {
    let w = world().await?;
    w.signer.call("set_fail").args_json(json!({ "fail": true })).transact().await?.into_result()?;
    let r = w.agent_call("request_sign", json!({ "req": sign_req(5) })).await?;
    assert!(r.is_success(), "callback must not panic: {:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "sign_failed");
    assert_eq!(event_names(&r), ["request_allowed", "sign_failed"]);
    assert_eq!(w.spent().await?, 0);
    Ok(())
}

#[tokio::test]
async fn swap_allow_funds_deposit_address() -> Result<()> {
    let w = world().await?;
    let deposit = w.worker.dev_create_account().await?;
    let q = w.quote(deposit.id().as_str(), 6_000_000);
    let r = w.agent_call("request_swap", json!({ "quote": q.clone() })).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "funded", "{o}");
    assert_eq!(o["deposit_address"], deposit.id().as_str());
    assert_eq!(event_names(&r), ["request_allowed", "swap_funded"]);
    assert_eq!(w.ft_balance(deposit.id().as_str()).await?, 6_000_000);
    assert_eq!(w.ft_balance(w.guardrail.id().as_str()).await?, 94_000_000);
    assert_eq!(w.spent().await?, 600);
    println!("GAS request_swap allow->funded: {} TGas", r.total_gas_burnt.as_tgas());
    // replay
    let r = w.agent_call("request_swap", json!({ "quote": q })).await?;
    let o = out(&r);
    assert_eq!(o["rule"], "quote_consumed");
    Ok(())
}

#[tokio::test]
async fn swap_tampered_quote_denied() -> Result<()> {
    let w = world().await?;
    let mut q = w.quote("mallory.test.near", 6_000_000);
    q["quote"]["depositAddress"] = json!("other.test.near");
    let r = w.agent_call("request_swap", json!({ "quote": q })).await?;
    let o = out(&r);
    assert_eq!(o["rule"], "quote_signature");
    assert_eq!(w.ft_balance(w.guardrail.id().as_str()).await?, 100_000_000);
    Ok(())
}

#[tokio::test]
async fn swap_funding_failure_refunds_and_unconsumes() -> Result<()> {
    let w = world().await?;
    w.ft.call("set_fail").args_json(json!({ "fail": true })).transact().await?.into_result()?;
    let deposit = w.worker.dev_create_account().await?;
    let q = w.quote(deposit.id().as_str(), 6_000_000);
    let r = w.agent_call("request_swap", json!({ "quote": q.clone() })).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let o = out(&r);
    assert_eq!(o["status"], "fund_failed");
    assert_eq!(w.spent().await?, 0);
    // same quote can be retried once the token works again
    w.ft.call("set_fail").args_json(json!({ "fail": false })).transact().await?.into_result()?;
    let r = w.agent_call("request_swap", json!({ "quote": q })).await?;
    let o = out(&r);
    assert_eq!(o["status"], "funded", "{o}");
    Ok(())
}

#[tokio::test]
async fn pause_and_unpause() -> Result<()> {
    let w = world().await?;
    w.owner.call(w.guardrail.id(), "pause").transact().await?.into_result()?;
    let r = w.agent_call("request_sign", json!({ "req": sign_req(1) })).await?;
    let o = out(&r);
    assert_eq!(o["rule"], "paused");
    w.owner.call(w.guardrail.id(), "unpause").transact().await?.into_result()?;
    let r = w.agent_call("request_sign", json!({ "req": sign_req(1) })).await?;
    let o = out(&r);
    assert_eq!(o["status"], "signed");
    Ok(())
}

#[tokio::test]
async fn agent_key_is_protocol_restricted_to_two_methods() -> Result<()> {
    let w = world().await?;
    for m in ["set_policy", "pause", "withdraw", "add_agent_key", "approve"] {
        let r = w.agent_call(m, json!({})).await;
        // either rejected at the protocol level (error before execution) or a failed receipt
        match r {
            Ok(res) => assert!(res.is_failure(), "{m} must fail"),
            Err(_) => {}
        }
    }
    // and the key cannot be used to move NEAR directly
    let r = w.agent.transfer_near(w.owner.id(), NearToken::from_near(1)).await;
    assert!(r.is_err() || r.unwrap().is_failure());
    // the owner can delete the deployer's full-access key(s), leaving only the agent FC key
    let keys = w.worker.view_access_keys(w.guardrail.id()).await?;
    let fa: Vec<_> = keys.iter().filter(|k| matches!(k.access_key.permission, near_workspaces::types::AccessKeyPermission::FullAccess)).collect();
    assert!(!fa.is_empty(), "dev_deploy leaves a full-access key");
    for k in &fa {
        let r = w.owner.call(w.guardrail.id(), "delete_account_key").args_json(json!({ "public_key": k.public_key.to_string() })).transact().await?;
        assert!(r.is_success(), "{:?}", r.failures());
    }
    let keys = w.worker.view_access_keys(w.guardrail.id()).await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].public_key.to_string(), w.agent_pk);
    // and the contract still works through the agent key afterwards
    let r = w.agent_call("request_sign", json!({ "req": sign_req(1) })).await?;
    let o = out(&r);
    assert_eq!(o["status"], "signed");
    Ok(())
}
