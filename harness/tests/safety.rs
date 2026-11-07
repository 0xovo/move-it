use std::process::Command;

#[test]
fn unsafe_commands_refuse_before_opening_app_state_or_keys() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    for args in [
        vec!["api", "move_start", "--state", state.to_str().unwrap()],
        vec!["api", "local_move", "brave", "chrome", "--state", state.to_str().unwrap()],
        vec!["open", "chrome", "/", "missing.box"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_moveit-harness")).args(args).output().unwrap();
        assert!(!output.status.success());
        let message = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(message.contains("scratch"), "{message}");
        assert!(!state.exists());
    }
}
