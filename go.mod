module github.com/elastos/Elastos.ELA.SideChain.ESC

go 1.16

replace (
	github.com/elastos/Elastos.ELA => ../Elastos.ELA
	github.com/elastos/Elastos.ELA.SPV => ../Elastos.ELA.SPV
	github.com/elastos/Elastos.ELA.SideChain => ../Elastos.ELA.SideChain
)

require (
	github.com/allegro/bigcache v1.2.1
	github.com/apilayer/freegeoip v3.5.0+incompatible
	github.com/aristanetworks/goarista v0.0.0-20210715113802-a1396632fc37
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/cespare/cp v1.1.1
	github.com/cloudflare/cloudflare-go v0.21.0
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.7.1
	github.com/docker/docker v20.10.8+incompatible
	github.com/edsrzf/mmap-go v1.0.0
	github.com/elastic/gosigar v0.14.1
	github.com/elastos/Elastos.ELA v0.7.0
	github.com/elastos/Elastos.ELA.SPV v0.0.7
	github.com/elastos/Elastos.ELA.SideChain v0.2.0
	github.com/fatih/color v1.12.0
	github.com/fjl/memsize v0.0.1
	github.com/gballet/go-libpcsclite v0.0.0-20191108122812-4678299bea08
	github.com/go-stack/stack v1.8.1
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4
	github.com/gorilla/websocket v1.4.2
	github.com/graph-gophers/graphql-go v1.1.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/howeyc/fsnotify v0.9.0 // indirect
	github.com/huin/goupnp v1.0.2
	github.com/influxdata/influxdb v1.9.3
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mattn/go-colorable v0.1.8
	github.com/mattn/go-isatty v0.0.13
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/naoina/toml v0.1.1
	github.com/olebedev/go-duktape v0.0.0-20210326210528-650f7c854440
	github.com/olekukonko/tablewriter v0.0.5
	github.com/oschwald/maxminddb-golang v1.8.0 // indirect
	github.com/pborman/uuid v1.2.1
	github.com/peterh/liner v1.2.1
	github.com/prometheus/tsdb v0.10.0
	github.com/rjeczalik/notify v0.9.2
	github.com/robertkrimen/otto v0.0.0-20210614181706-373ff5438452
	github.com/rs/cors v1.8.0
	github.com/status-im/keycard-go v0.0.0-20200402102358-957c09536969
	github.com/steakknife/bloomfilter v0.0.0-20180922174646-6819c0d2a570
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/wsddn/go-ecdh v0.0.0-20161211032359-48726bab9208
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/net v0.0.0-20210825183410-e898025ed96a
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf
	golang.org/x/text v0.3.7
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
	gotest.tools/v3 v3.0.3 // indirect
)
