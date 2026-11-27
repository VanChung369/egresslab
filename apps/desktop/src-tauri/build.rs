fn main() {
    // Lets the tests pick the sidecar built for this target.
    println!(
        "cargo:rustc-env=EGRESSLAB_TARGET_TRIPLE={}",
        std::env::var("TARGET").expect("cargo sets TARGET")
    );

    tauri_build::build()
}
