#[uniffi::export]
fn hello() -> Vec<u8>{
println!("baba");
Vec::new()
}


uniffi::setup_scaffolding!();
