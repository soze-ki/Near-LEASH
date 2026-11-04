//! EVM transaction construction. The agent supplies structured fields; the
//! contract builds the EIP-1559 payload, so the bytes that get signed are the
//! bytes the policy saw. There is no RLP decoding anywhere in this contract.

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::near;
use omni_transaction::evm::types::Signature as EvmSignature;
use omni_transaction::evm::EVMTransaction;

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub chain_id: u64,
    /// 0x-prefixed 20-byte hex, any case.
    pub to: String,
    /// wei
    pub value: U128,
    /// calldata; omit or empty for a plain transfer
    pub data: Option<Base64VecU8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: U128,
    pub max_priority_fee_per_gas: U128,
    /// derivation path label; must be in `policy.evm.paths`
    pub path: String,
    /// agent's stated purpose, logged verbatim, never trusted
    pub intent_note: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    BadAddress,
    DataTooLong,
    /// Selector is `transfer(address,uint256)` but the ABI encoding is not
    /// exactly one address word and one uint256 word that fits in u128.
    BadErc20Transfer,
}

/// ERC-20 `transfer(address,uint256)` selector.
pub const ERC20_TRANSFER_SELECTOR: &str = "0xa9059cbb";

/// Decoded ERC-20 `transfer` call. The policy applies the recipient allowlist
/// to `recipient` (not to the token contract) and values `amount` with the
/// token's price, so an agent cannot hide a transfer inside calldata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erc20Transfer {
    /// lower-case 0x recipient address decoded from calldata
    pub recipient: String,
    /// token units (raw, pre-decimals)
    pub amount: u128,
}

/// Strict decode of `transfer(address,uint256)` calldata: 4 + 32 + 32 bytes,
/// address word zero-padded, amount word must fit in u128.
pub fn decode_erc20_transfer(data: &[u8]) -> Result<Erc20Transfer, BuildError> {
    if data.len() != 68 || !data[4..16].iter().all(|b| *b == 0) || !data[36..52].iter().all(|b| *b == 0) {
        return Err(BuildError::BadErc20Transfer);
    }
    let recipient = format!("0x{}", hex::encode(&data[16..36]));
    let amount = u128::from_be_bytes(data[52..68].try_into().expect("16 bytes"));
    Ok(Erc20Transfer { recipient, amount })
}

#[derive(Debug)]
pub struct Built {
    pub tx: EVMTransaction,
    /// lower-case 0x address
    pub to_norm: String,
    /// lower-case 0x 4-byte selector if calldata is >= 4 bytes
    pub selector: Option<String>,
    /// Decoded ERC-20 transfer when `selector` is `transfer(address,uint256)`.
    pub erc20: Option<Erc20Transfer>,
    /// RLP(0x02 || tx) ready to be keccak'd and signed
    pub unsigned: Vec<u8>,
}

pub const MAX_CALLDATA: usize = 4096;

pub fn normalise_address(s: &str) -> Result<([u8; 20], String), BuildError> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).ok_or(BuildError::BadAddress)?;
    if h.len() != 40 {
        return Err(BuildError::BadAddress);
    }
    let bytes = hex::decode(h).map_err(|_| BuildError::BadAddress)?;
    let arr: [u8; 20] = bytes.try_into().map_err(|_| BuildError::BadAddress)?;
    Ok((arr, format!("0x{}", h.to_ascii_lowercase())))
}

pub fn build(req: &SignRequest) -> Result<Built, BuildError> {
    let (to, to_norm) = normalise_address(&req.to)?;
    let data = req.data.as_ref().map(|d| d.0.clone()).unwrap_or_default();
    if data.len() > MAX_CALLDATA {
        return Err(BuildError::DataTooLong);
    }
    let selector = if data.len() >= 4 { Some(format!("0x{}", hex::encode(&data[..4]))) } else { None };
    let erc20 = match selector.as_deref() {
        Some(ERC20_TRANSFER_SELECTOR) => Some(decode_erc20_transfer(&data)?),
        _ => None,
    };
    let tx = EVMTransaction {
        chain_id: req.chain_id,
        nonce: req.nonce,
        to: Some(to),
        value: req.value.0,
        input: data,
        gas_limit: req.gas_limit as u128,
        max_fee_per_gas: req.max_fee_per_gas.0,
        max_priority_fee_per_gas: req.max_priority_fee_per_gas.0,
        access_list: vec![],
    };
    let unsigned = tx.build_for_signing();
    Ok(Built { tx, to_norm, selector, erc20, unsigned })
}

/// Worst-case native cost of the tx: value + gas_limit * max_fee_per_gas.
pub fn max_native_cost_wei(req: &SignRequest) -> u128 {
    req.value
        .0
        .saturating_add((req.gas_limit as u128).saturating_mul(req.max_fee_per_gas.0))
}

/// Convert wei to USD cents using the policy's static rate (cents per 1e18 wei).
pub fn wei_to_usd_cents(wei: u128, usd_cents_per_native: u64) -> u64 {
    // (wei * cents) / 1e18, computed in u128 then clamped
    let v = wei.saturating_mul(usd_cents_per_native as u128) / 1_000_000_000_000_000_000u128;
    v.min(u64::MAX as u128) as u64
}

/// Assemble the broadcastable raw transaction from the MPC signature.
/// `recovery_id` is the MPC's `recovery_id` (0/1); EIP-1559 `v` is the same.
pub fn with_signature(tx: &EVMTransaction, r: [u8; 32], s: [u8; 32], recovery_id: u8) -> Vec<u8> {
    tx.build_with_signature(&EvmSignature { v: recovery_id as u64, r: r.to_vec(), s: s.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> SignRequest {
        SignRequest {
            chain_id: 84532,
            to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into(),
            value: U128(10_000_000_000_000_000),
            data: None,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: U128(20_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000_000),
            path: "treasury-base".into(),
            intent_note: "test".into(),
        }
    }

    #[test]
    fn builds_eip1559_with_type_prefix() {
        let b = build(&req()).unwrap();
        assert_eq!(b.unsigned[0], 0x02);
        assert_eq!(b.to_norm, "0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
        assert!(b.selector.is_none());
    }

    fn transfer_calldata(recipient: &str, amount: u128) -> Vec<u8> {
        let mut d = hex::decode("a9059cbb").unwrap();
        d.extend([0u8; 12]);
        d.extend(hex::decode(recipient.trim_start_matches("0x")).unwrap());
        d.extend([0u8; 16]);
        d.extend(amount.to_be_bytes());
        d
    }

    #[test]
    fn selector_from_calldata() {
        let mut r = req();
        r.data = Some(Base64VecU8(hex::decode("095ea7b3000000").unwrap()));
        let b = build(&r).unwrap();
        assert_eq!(b.selector.as_deref(), Some("0x095ea7b3"));
        assert!(b.erc20.is_none());
    }

    #[test]
    fn erc20_transfer_is_decoded() {
        let mut r = req();
        r.data = Some(Base64VecU8(transfer_calldata("0x000000000000000000000000000000000000BEEF", 1_500_000)));
        let b = build(&r).unwrap();
        assert_eq!(b.selector.as_deref(), Some("0xa9059cbb"));
        assert_eq!(
            b.erc20,
            Some(Erc20Transfer { recipient: "0x000000000000000000000000000000000000beef".into(), amount: 1_500_000 })
        );
    }

    #[test]
    fn malformed_erc20_transfer_is_rejected() {
        // truncated
        let mut r = req();
        r.data = Some(Base64VecU8(hex::decode("a9059cbb000000").unwrap()));
        assert_eq!(build(&r).unwrap_err(), BuildError::BadErc20Transfer);
        // dirty address padding
        let mut d = transfer_calldata("0x000000000000000000000000000000000000beef", 1);
        d[5] = 1;
        r.data = Some(Base64VecU8(d));
        assert_eq!(build(&r).unwrap_err(), BuildError::BadErc20Transfer);
        // amount above u128
        let mut d = transfer_calldata("0x000000000000000000000000000000000000beef", 1);
        d[40] = 1;
        r.data = Some(Base64VecU8(d));
        assert_eq!(build(&r).unwrap_err(), BuildError::BadErc20Transfer);
        // trailing bytes
        let mut d = transfer_calldata("0x000000000000000000000000000000000000beef", 1);
        d.push(0);
        r.data = Some(Base64VecU8(d));
        assert_eq!(build(&r).unwrap_err(), BuildError::BadErc20Transfer);
    }

    #[test]
    fn rejects_bad_address_and_long_data() {
        let mut r = req();
        r.to = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into();
        assert_eq!(build(&r).unwrap_err(), BuildError::BadAddress);
        r.to = "0x1234".into();
        assert_eq!(build(&r).unwrap_err(), BuildError::BadAddress);
        let mut r = req();
        r.data = Some(Base64VecU8(vec![0; MAX_CALLDATA + 1]));
        assert_eq!(build(&r).unwrap_err(), BuildError::DataTooLong);
    }

    #[test]
    fn usd_valuation() {
        // 0.01 ETH value + 21000 * 20 gwei = 0.01042 ETH at $3000 -> 3126 cents
        let c = wei_to_usd_cents(max_native_cost_wei(&req()), 300_000);
        assert_eq!(c, 3126);
    }
}
