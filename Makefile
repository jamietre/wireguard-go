CROSS_CC  = aarch64-linux-gnu-gcc
GOOS      = linux
GOARCH    = arm64
CGO       = 0

.PHONY: all wireguard-go wg admin clean

all: bin/wireguard-go bin/wg bin/wg-admin

bin/wireguard-go:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO) go build -o $@ .

bin/wg:
	$(MAKE) -C wireguard-tools/src CC=$(CROSS_CC) WITH_WGQUICK=no LDFLAGS="-static"
	cp wireguard-tools/src/wg $@

admin/go.sum: admin/go.mod admin/*.go
	cd admin && go mod tidy

bin/wg-admin: admin/go.sum admin/*.go
	cd admin && GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO) go build -o ../bin/wg-admin .

clean:
	rm -f bin/wireguard-go bin/wg bin/wg-admin
	$(MAKE) -C wireguard-tools/src clean
