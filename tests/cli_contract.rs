use predicates::prelude::PredicateBooleanExt;

#[test]
fn help_exposes_the_v1_commands() {
    let mut command = assert_cmd::Command::cargo_bin("carl").unwrap();
    command.arg("--help").assert().success().stdout(
        predicates::str::contains("serve")
            .and(predicates::str::contains("auth"))
            .and(predicates::str::contains("memory"))
            .and(predicates::str::contains("pair"))
            .and(predicates::str::contains("doctor"))
            .and(predicates::str::contains("sessions")),
    );
}
