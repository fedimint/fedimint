fn main() {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/gwlightning.proto"], &["proto/"])
        .expect("Failed to compile gateway proto files");
    fedimint_build::print_git_hash();
}
