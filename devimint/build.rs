use std::env;

pub const FM_DEVIMINT_STATIC_DATA_DIR_ENV: &str = "FM_DEVIMINT_STATIC_DATA_DIR";

fn main() {
    fedimint_build::set_code_version();
    fedimint_build::set_large_page_size();

    println!("cargo:rerun-if-env-changed={FM_DEVIMINT_STATIC_DATA_DIR_ENV}");

    if let Ok(data_dir) = env::var(FM_DEVIMINT_STATIC_DATA_DIR_ENV) {
        // For Nix, and anyone else that is willing to customize
        println!("cargo:rustc-env={FM_DEVIMINT_STATIC_DATA_DIR_ENV}={data_dir}");
    } else {
        // For "classic" distros following Linux FHS
        println!("cargo:rustc-env={FM_DEVIMINT_STATIC_DATA_DIR_ENV}=/usr/share/devimint");
    }
}
