use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Sub};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CurrencyError {
    #[error("Overflow occurred in currency calculation")]
    Overflow,
    #[error("Underflow occurred in currency calculation")]
    Underflow,
    #[error("Invalid amount string format: {0}")]
    InvalidFormat(String),
}

/// Exact fixed-point South African Rand (ZAR) representation stored in minor units (cents).
/// Prevents floating-point precision bugs in FinTech ledger pipelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct ZarAmount {
    cents: i64,
}

impl ZarAmount {
    pub const ZERO: ZarAmount = ZarAmount { cents: 0 };

    pub fn from_cents(cents: i64) -> Self {
        Self { cents }
    }

    pub fn from_rands_and_cents(rands: i64, cents: i64) -> Result<Self, CurrencyError> {
        let total = rands
            .checked_mul(100)
            .and_then(|r| r.checked_add(cents))
            .ok_or(CurrencyError::Overflow)?;
        Ok(Self { cents: total })
    }

    pub fn cents(&self) -> i64 {
        self.cents
    }

    pub fn is_zero(&self) -> bool {
        self.cents == 0
    }

    pub fn is_positive(&self) -> bool {
        self.cents > 0
    }

    pub fn is_negative(&self) -> bool {
        self.cents < 0
    }

    pub fn abs(&self) -> Self {
        Self {
            cents: self.cents.abs(),
        }
    }

    pub fn checked_add(self, other: Self) -> Result<Self, CurrencyError> {
        self.cents
            .checked_add(other.cents)
            .map(|cents| Self { cents })
            .ok_or(CurrencyError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, CurrencyError> {
        self.cents
            .checked_sub(other.cents)
            .map(|cents| Self { cents })
            .ok_or(CurrencyError::Underflow)
    }
}

impl Add for ZarAmount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).expect("ZarAmount addition overflow")
    }
}

impl Sub for ZarAmount {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("ZarAmount subtraction overflow")
    }
}

impl fmt::Display for ZarAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_neg = self.cents < 0;
        let abs_cents = self.cents.abs();
        let rands = abs_cents / 100;
        let rem_cents = abs_cents % 100;
        if is_neg {
            write!(f, "-R{}.{:02}", rands, rem_cents)
        } else {
            write!(f, "R{}.{:02}", rands, rem_cents)
        }
    }
}
