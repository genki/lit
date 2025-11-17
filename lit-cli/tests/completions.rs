use std::process::Command;

#[test]
fn generates_bash_completions() {
    let output = Command::new(env!("CARGO_BIN_EXE_lit"))
        .args(["completions", "bash"])
        .output()
        .expect("run lit completions");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete"));
}
