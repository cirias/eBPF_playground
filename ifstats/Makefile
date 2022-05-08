build: bpf_bpfel.go main.go
	go build

bpf_bpfel.o bpf_bpfel.go: stats.c generate.go
	go generate
