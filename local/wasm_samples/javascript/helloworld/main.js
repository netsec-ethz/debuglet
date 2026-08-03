// Minimal "hello world" debuglet in JavaScript, compiled to WASM with Javy.
//
// Javy bundles the QuickJS engine into a self-contained wasip1 command module.
// console.log is streamed back to the user as stdout.
//
// NOTE: Javy guests run pure JS over QuickJS and cannot import the executor's
// custom host functions (connect_tcp, etc.), so JavaScript debuglets are limited
// to compute and stdout — networking samples (ping, throughput) are not available
// in JS. Use Go, Rust, or C for measurements that touch the network.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/javascript/helloworld

console.log("Hello from Debuglet! (JavaScript)");
