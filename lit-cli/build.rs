fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../proto/relay.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&[proto], &["../proto"])?;
    Ok(())
}
