package main

import (
	"fmt"

	"github.com/dop251/goja"
)

func main() {
	vm := goja.New()

	_, err := vm.RunString(`
function sum(a, b) {
    return a+b;
}
`)
	if err != nil {
		panic(err)
	}
	sum, ok := goja.AssertFunction(vm.Get("sum"))
	if !ok {
		panic("Not a function")
	}

	res, err := sum(goja.Undefined(), vm.ToValue(40), vm.ToValue(2))
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
