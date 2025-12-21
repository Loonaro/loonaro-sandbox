use std::io::Result;

fn main() -> Result<()> {
    // This points prost to the pre-compiled binary
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());

    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    let root = std::env::current_dir()?;
    let proto_root = root.join("../../../shared/proto");
    let proto_file = proto_root.join("sigma.proto");

    // We don't need special include environment variables here
    config.compile_protos(&[proto_file], &[proto_root])?;
    Ok(())
}
