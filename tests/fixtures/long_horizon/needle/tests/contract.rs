use carl_long_horizon_needle::{NEEDLE, completed_epochs};

#[test]
fn fixture_requires_completed_needle() {
    assert_eq!(NEEDLE, "needle_7f3a91c2");
    assert_eq!(completed_epochs(), 1);
}
