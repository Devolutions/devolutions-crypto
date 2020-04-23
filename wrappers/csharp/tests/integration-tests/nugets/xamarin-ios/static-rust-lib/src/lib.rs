#[no_mangle]
pub extern "C" fn foo() -> Box<i32> {
    Box::new(5)
}