module github.com/metacubex/mipstack/interop/gvisor

go 1.20

require (
	github.com/metacubex/gvisor v0.0.0-20260810011720-3cc44cf9ac22
	github.com/metacubex/mipstack v0.0.0
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/time v0.10.0 // indirect
)

replace github.com/metacubex/mipstack => ../..
