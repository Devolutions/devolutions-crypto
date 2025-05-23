fn main() {
    uniffi_dart::generate_scaffolding("./src/devolutions_crypto.udl".into()).unwrap();
}
