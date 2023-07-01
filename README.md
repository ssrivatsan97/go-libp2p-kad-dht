# go-libp2p-kad-dht

This fork adds censorship attack detection and mitigation to `go-libp2p-kad-dht`. This fork diverges from github.com/libp2p/go-libp2p-kad-dht after v0.20.0. 

Clone this repository. Also clone github.com/ipfs/kubo.

Launch the ipfs daemon.
```
cd kubo
go run ./cmd/ipfs daemon
```

To find providers for a cid `cid`, run `go run ./cmd/ipfs dht findprovs cid` in another terminal. Check the terminal window where you ran ipfs daemon for log messages.

To provide a file, do the following:\
1. Create a new file `echo "hello" > ../hello.txt`
1. In a new terminal window, run `go run ./cmd/ipfs add ../hello.txt`.

For greater flexibility, you can run your own DHT node. This will allow you to enable/disable mitigation, and provide, find providers and detect censorship attacks through code, and also measure relevant parameters.