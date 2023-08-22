use std::env;

fn main() {
    let cdir = env::current_dir().expect("failed to get current directory");
    let include_path = cdir.join("proto");
    let proto_path = include_path.join("gateway_lnrpc.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&[proto_path], &[include_path])
        .unwrap_or_else(|e| panic!("failed to compile gateway proto files: {e}"));

    fedimint_build::set_code_version();
}
