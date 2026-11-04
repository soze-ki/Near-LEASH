//! Mock of `v1.signer`: `sign` returns a fixed secp256k1-shaped response (the
//! MPC v2 shape chainsig.js handles) or panics when `fail` is set.
use near_sdk::serde_json::{json, Value};
use near_sdk::{env, near, require, NearToken};

#[near(contract_state)]
#[derive(Default)]
pub struct MockSigner {
    fail: bool,
    calls: u64,
}

#[near]
impl MockSigner {
    pub fn set_fail(&mut self, fail: bool) {
        self.fail = fail;
    }
    pub fn calls(&self) -> u64 {
        self.calls
    }
    #[payable]
    pub fn sign(&mut self, request: Value) -> Value {
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "deposit");
        require!(request["payload_v2"]["Ecdsa"].as_str().map(|s| s.len() == 64).unwrap_or(false), "payload");
        require!(request["path"].is_string() && request["domain_id"] == 0, "args");
        self.calls += 1;
        if self.fail {
            env::panic_str("mpc: signature generation failed");
        }
        json!({
            "scheme": "Secp256k1",
            "big_r": {"affine_point": format!("02{}", "11".repeat(32))},
            "s": {"scalar": "22".repeat(32)},
            "recovery_id": 0
        })
    }
}
