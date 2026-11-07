pub mod currency;
pub mod double_entry;
pub mod escrow;
pub mod vat;

pub use currency::*;
pub use double_entry::*;
pub use escrow::*;
pub use vat::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zar_amount_math() {
        let a = ZarAmount::from_rands_and_cents(150, 50).unwrap();
        let b = ZarAmount::from_rands_and_cents(49, 50).unwrap();
        let sum = a + b;
        assert_eq!(sum.cents(), 20000);
        assert_eq!(sum.to_string(), "R200.00");
    }

    #[test]
    fn test_sars_vat_calculation() {
        // R100.00 net + 15% VAT = R115.00 gross
        let net = ZarAmount::from_cents(10000);
        let breakdown = calculate_vat_exclusive(net).unwrap();
        assert_eq!(breakdown.vat_amount.cents(), 1500);
        assert_eq!(breakdown.gross_amount.cents(), 11500);

        // Inclusive from R115.00 should yield R100.00 net and R15.00 VAT
        let inc_breakdown = calculate_vat_inclusive(breakdown.gross_amount).unwrap();
        assert_eq!(inc_breakdown.net_amount.cents(), 10000);
        assert_eq!(inc_breakdown.vat_amount.cents(), 1500);
    }

    #[test]
    fn test_double_entry_balance_invariant() {
        let mut tx = LedgerTransaction::new("tx_001", "Customer Payment", 1700000000);
        // Dr Bank R115.00, Cr Revenue R100.00, Cr VAT Output R15.00
        tx.add_debit("Bank:Nedbank", ZarAmount::from_cents(11500));
        tx.add_credit("Revenue:Services", ZarAmount::from_cents(10000));
        tx.add_credit("Liability:SARS_VAT_Output", ZarAmount::from_cents(1500));

        assert!(tx.verify_balance().is_ok());
    }

    #[test]
    fn test_double_entry_unbalanced_fails() {
        let mut tx = LedgerTransaction::new("tx_002", "Unbalanced payment", 1700000000);
        tx.add_debit("Bank:Nedbank", ZarAmount::from_cents(10000));
        tx.add_credit("Revenue:Services", ZarAmount::from_cents(9000));

        let res = tx.verify_balance();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            LedgerError::UnbalancedTransaction {
                debits: ZarAmount::from_cents(10000),
                credits: ZarAmount::from_cents(9000),
            }
        );
    }

    #[test]
    fn test_escrow_lifecycle() {
        let mut escrow = EscrowAccount::new(
            "escrow_101",
            "buyer@school.co.za",
            "tutor@tutoring.co.za",
            Some("arbiter@platform.co.za".to_string()),
            ZarAmount::from_cents(50000), // R500.00
        );

        assert_eq!(escrow.state, EscrowState::Initiated);
        escrow.fund(ZarAmount::from_cents(50000)).unwrap();
        assert_eq!(escrow.state, EscrowState::Funded);

        escrow.start_inspection().unwrap();
        assert_eq!(escrow.state, EscrowState::Inspection);

        let payout = escrow.release_funds().unwrap();
        assert_eq!(payout.cents(), 50000);
        assert_eq!(escrow.state, EscrowState::Released);
        assert_eq!(escrow.held_balance, ZarAmount::ZERO);

        // Cannot release again
        assert_eq!(escrow.release_funds().unwrap_err(), EscrowError::AlreadySettled);
    }
}
