use crate::currency::ZarAmount;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum EscrowError {
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: EscrowState,
        to: EscrowState,
    },
    #[error("Insufficient funds in escrow: requested {requested}, available {available}")]
    InsufficientFunds {
        requested: ZarAmount,
        available: ZarAmount,
    },
    #[error("Escrow is already settled")]
    AlreadySettled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowState {
    Initiated,
    Funded,
    Inspection,
    Released,
    Refunded,
    Disputed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscrowAccount {
    pub escrow_id: String,
    pub buyer_account: String,
    pub seller_account: String,
    pub arbiter_account: Option<String>,
    pub total_amount: ZarAmount,
    pub held_balance: ZarAmount,
    pub state: EscrowState,
}

impl EscrowAccount {
    pub fn new(
        escrow_id: impl Into<String>,
        buyer_account: impl Into<String>,
        seller_account: impl Into<String>,
        arbiter_account: Option<String>,
        total_amount: ZarAmount,
    ) -> Self {
        Self {
            escrow_id: escrow_id.into(),
            buyer_account: buyer_account.into(),
            seller_account: seller_account.into(),
            arbiter_account,
            total_amount,
            held_balance: ZarAmount::ZERO,
            state: EscrowState::Initiated,
        }
    }

    /// Deposit funds into the escrow
    pub fn fund(&mut self, amount: ZarAmount) -> Result<(), EscrowError> {
        if self.state != EscrowState::Initiated && self.state != EscrowState::Funded {
            return Err(EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Funded,
            });
        }

        self.held_balance = self
            .held_balance
            .checked_add(amount)
            .map_err(|_| EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Funded,
            })?;

        if self.held_balance >= self.total_amount {
            self.state = EscrowState::Funded;
        }

        Ok(())
    }

    /// Move escrow to inspection period
    pub fn start_inspection(&mut self) -> Result<(), EscrowError> {
        if self.state != EscrowState::Funded {
            return Err(EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Inspection,
            });
        }
        self.state = EscrowState::Inspection;
        Ok(())
    }

    /// Raise a dispute during inspection
    pub fn dispute(&mut self) -> Result<(), EscrowError> {
        if self.state != EscrowState::Inspection && self.state != EscrowState::Funded {
            return Err(EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Disputed,
            });
        }
        self.state = EscrowState::Disputed;
        Ok(())
    }

    /// Release funds to the seller
    pub fn release_funds(&mut self) -> Result<ZarAmount, EscrowError> {
        match self.state {
            EscrowState::Funded | EscrowState::Inspection | EscrowState::Disputed => {
                let payout = self.held_balance;
                self.held_balance = ZarAmount::ZERO;
                self.state = EscrowState::Released;
                Ok(payout)
            }
            EscrowState::Released | EscrowState::Refunded => Err(EscrowError::AlreadySettled),
            EscrowState::Initiated => Err(EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Released,
            }),
        }
    }

    /// Refund funds back to the buyer
    pub fn refund_buyer(&mut self) -> Result<ZarAmount, EscrowError> {
        match self.state {
            EscrowState::Funded | EscrowState::Inspection | EscrowState::Disputed => {
                let refund = self.held_balance;
                self.held_balance = ZarAmount::ZERO;
                self.state = EscrowState::Refunded;
                Ok(refund)
            }
            EscrowState::Released | EscrowState::Refunded => Err(EscrowError::AlreadySettled),
            EscrowState::Initiated => Err(EscrowError::InvalidTransition {
                from: self.state,
                to: EscrowState::Refunded,
            }),
        }
    }
}
