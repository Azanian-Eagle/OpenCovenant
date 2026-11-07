use crate::currency::{CurrencyError, ZarAmount};
use serde::{Deserialize, Serialize};

/// Standard South African Revenue Service (SARS) Value Added Tax (15%).
pub const SARS_VAT_RATE_PERCENT: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VatBreakdown {
    pub net_amount: ZarAmount,
    pub vat_amount: ZarAmount,
    pub gross_amount: ZarAmount,
}

/// Calculate standard SARS 15% VAT on an exclusive (net) amount.
/// Rounding follows standard half-up / banker rounding to nearest cent.
pub fn calculate_vat_exclusive(net: ZarAmount) -> Result<VatBreakdown, CurrencyError> {
    // vat = round(net_cents * 15 / 100)
    let net_cents = net.cents();
    let vat_cents = (net_cents * 15 + 50) / 100;
    let vat = ZarAmount::from_cents(vat_cents);
    let gross = net.checked_add(vat)?;

    Ok(VatBreakdown {
        net_amount: net,
        vat_amount: vat,
        gross_amount: gross,
    })
}

/// Extract standard SARS 15% VAT from an inclusive (gross) amount.
/// Formula: net = gross / 1.15 => (gross * 100 + 57) / 115
pub fn calculate_vat_inclusive(gross: ZarAmount) -> Result<VatBreakdown, CurrencyError> {
    let gross_cents = gross.cents();
    let net_cents = (gross_cents * 100 + 57) / 115;
    let net = ZarAmount::from_cents(net_cents);
    let vat = gross.checked_sub(net)?;

    Ok(VatBreakdown {
        net_amount: net,
        vat_amount: vat,
        gross_amount: gross,
    })
}
