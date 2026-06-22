package main

//go:wasmimport env host_func
func host_func() int32

//go:wasmexport loop_call_host
func loop_call_host(n int32) {
	for range n {
		i := host_func()
		if i < 0 {
			return
		}
	}
}

func main() {}
