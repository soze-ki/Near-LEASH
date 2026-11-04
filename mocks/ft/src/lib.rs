//! Minimal NEP-141 mock: `mint`, `ft_transfer`, `ft_balance_of`, and a
//! `set_fail` switch so `ft_transfer` can be made to panic.
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockFt {
    balances: LookupMap<AccountId, u128>,
    fail: bool,
}

#[near]
impl MockFt {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b"), fail: false }
    }
    pub fn set_fail(&mut self, fail: bool) {
        self.fail = fail;
    }
    pub fn mint(&mut self, account_id: AccountId, amount: U128) {
        let b = self.balances.get(&account_id).copied().unwrap_or(0);
        self.balances.insert(account_id, b + amount.0);
    }
    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        U128(self.balances.get(&account_id).copied().unwrap_or(0))
    }
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "Requires attached deposit of exactly 1 yoctoNEAR");
        require!(!self.fail, "ft: transfer failed");
        let _ = memo;
        let sender = env::predecessor_account_id();
        let sb = self.balances.get(&sender).copied().unwrap_or(0);
        require!(sb >= amount.0, "The account doesn't have enough balance");
        self.balances.insert(sender, sb - amount.0);
        let rb = self.balances.get(&receiver_id).copied().unwrap_or(0);
        self.balances.insert(receiver_id, rb + amount.0);
    }
}
