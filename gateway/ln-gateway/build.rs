use std::env;

fn main() {
    let cdir = env::current_dir().expect("failed to get current directory");
    let include_path = cdir.join("proto");
    let proto_path = include_path.join("gatewaylnrpc.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&[proto_path], &[include_path])
        .unwrap_or_else(|e| panic!("failed to compile gateway proto files: {}", e));
    fedimint_build::print_git_hash();
}
