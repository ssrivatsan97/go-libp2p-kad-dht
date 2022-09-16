# go-libp2p-kad-dht

This repo adds eclipse attack detection functionality to `go-libp2p-kad-dht`.

Clone this repository. Also clone github.com/ipfs/kubo.

Do `cd kubo`. Launch the ipfs daemon by running `go run ./cmd/ipfs daemon`.

Create a new file `echo "hello" > ../hello.txt`

In a new terminal window, run `go run ./cmd/ipfs add ../hello.txt`. While running the provide operation, this libp2p package will also run eclipse detection.