use crate::currency::ZarAmount;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum LedgerError {
    #[error("Double-entry balance invariant violated: debits ({debits}) != credits ({credits})")]
    UnbalancedTransaction {
        debits: ZarAmount,
        credits: ZarAmount,
    },
    #[error("Transaction must have at least two entries (one debit and one credit)")]
    InsufficientEntries,
    #[error("Posting amounts must be strictly positive")]
    NonPositiveAmount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    Debit,
    Credit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPosting {
    pub account: String,
    pub entry_type: EntryType,
    pub amount: ZarAmount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTransaction {
    pub id: String,
    pub description: String,
    pub timestamp_epoch_sec: u64,
    pub postings: Vec<LedgerPosting>,
}

impl LedgerTransaction {
    pub fn new(id: impl Into<String>, description: impl Into<String>, timestamp_epoch_sec: u64) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            timestamp_epoch_sec,
            postings: Vec::new(),
        }
    }

    pub fn add_debit(&mut self, account: impl Into<String>, amount: ZarAmount) -> &mut Self {
        self.postings.push(LedgerPosting {
            account: account.into(),
            entry_type: EntryType::Debit,
            amount,
        });
        self
    }

    pub fn add_credit(&mut self, account: impl Into<String>, amount: ZarAmount) -> &mut Self {
        self.postings.push(LedgerPosting {
            account: account.into(),
            entry_type: EntryType::Credit,
            amount,
        });
        self
    }

    /// Enforces the fundamental SARB / NPS-Core double-entry invariant:
    /// sum(debits) == sum(credits)
    pub fn verify_balance(&self) -> Result<(), LedgerError> {
        if self.postings.len() < 2 {
            return Err(LedgerError::InsufficientEntries);
        }

        let mut total_debits = ZarAmount::ZERO;
        let mut total_credits = ZarAmount::ZERO;

        for posting in &self.postings {
            if !posting.amount.is_positive() {
                return Err(LedgerError::NonPositiveAmount);
            }
            match posting.entry_type {
                EntryType::Debit => {
                    total_debits = total_debits
                        .checked_add(posting.amount)
                        .map_err(|_| LedgerError::UnbalancedTransaction {
                            debits: total_debits,
                            credits: total_credits,
                        })?;
                }
                EntryType::Credit => {
                    total_credits = total_credits
                        .checked_add(posting.amount)
                        .map_err(|_| LedgerError::UnbalancedTransaction {
                            debits: total_debits,
                            credits: total_credits,
                        })?;
                }
            }
        }

        if total_debits != total_credits {
            return Err(LedgerError::UnbalancedTransaction {
                debits: total_debits,
                credits: total_credits,
            });
        }

        Ok(())
    }
}
