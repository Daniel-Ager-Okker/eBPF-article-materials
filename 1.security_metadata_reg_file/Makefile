.PHONY: all clean generate

CLANG ?= clang
CFLAGS := -target bpf -g -O2 -Wall

all: generate build

generate:
	go generate ./...

build:
	go build -o security_metadata_reg_file

clean:
	rm -f security_metadata_reg_file
	rm -f *_bpfel.go
	rm -f *_bpfeb.go
	rm -f *.o