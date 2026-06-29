// Minimal "hello world" debuglet in Rust.
//
// A debuglet is a WASI command module: write a normal `fn main()` and build it
// for wasm32-wasip1. The executor runs _start and streams stdout back to the
// user, so println! is all we need.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/rust/helloworld

fn main() {
    println!("Hello from Debuglet! (Rust)");
}
