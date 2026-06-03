#[cfg(not(target_arch = "wasm32"))]
fn main() {
    uniffi::uniffi_bindgen_main()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
