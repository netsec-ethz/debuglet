// Minimal "hello world" debuglet in Rust.
//
// The refactored engine runs WASI command modules: define `fn main()` and build
// for the wasm32-wasip1 target. stdout is streamed back to the user, so
// println! is all we need to report output.

fn main() {
    println!("Hello from Debuglet! (Rust)");
}
