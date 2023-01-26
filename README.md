# go-libp2p-kad-dht

NOTE: The branch `eclipse-det` has been merged into `master` and deleted for convenience. Just use the `master` branch now.

This repo adds eclipse attack detection functionality to `go-libp2p-kad-dht`.

Clone this repository. Also clone github.com/ipfs/kubo.

Do `cd kubo`. Launch the ipfs daemon by running `go run ./cmd/ipfs daemon`.

To find providers and also detect eclipse attack for a cid `cid`, run `go run ./cmd/ipfs dht findprovs cid` in another terminal. Check the terminal window where you ran ipfs daemon for log messages.

To run eclipse attack during Provide, do the following:
1. Uncomment lines 514-517 in routing.go (currently commented to avoid large amount of requests due to repeated provide operations)
2. Create a new file `echo "hello" > ../hello.txt`
3. In a new terminal window, run `go run ./cmd/ipfs add ../hello.txt`. While running the provide operation, this libp2p package will also run eclipse detection.
