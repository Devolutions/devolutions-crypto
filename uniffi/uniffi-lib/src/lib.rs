use devolutions_crypto::utils::generate_key;

#[uniffi::export]
fn hello() -> Vec<u8>{
println!("Generating Key in Rust!");
generate_key(32)
}




uniffi::setup_scaffolding!();
