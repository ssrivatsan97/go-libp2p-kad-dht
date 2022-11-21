package dht

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"

	kb "github.com/libp2p/go-libp2p-kbucket"
)

// GetClosestPeers is a Kademlia 'node lookup' operation. Returns a channel of
// the K closest peers to the given key.
//
// If the context is canceled, this function will return the context error along
// with the closest K peers it has found so far.
func (dht *IpfsDHT) GetClosestPeers(ctx context.Context, key string) ([]peer.ID, error) {
	if key == "" {
		return nil, fmt.Errorf("can't lookup empty key")
	}
	// TODO: I can break the interface! return []peer.ID
	lookupRes, err := dht.runLookupWithFollowup(ctx, key,
		func(ctx context.Context, p peer.ID) ([]*peer.AddrInfo, error) {
			// For DHT query command
			routing.PublishQueryEvent(ctx, &routing.QueryEvent{
				Type: routing.SendingQuery,
				ID:   p,
			})

			peers, err := dht.protoMessenger.GetClosestPeers(ctx, p, peer.ID(key))
			if err != nil {
				logger.Debugf("error getting closer peers: %s", err)
				return nil, err
			}

			// For DHT query command
			routing.PublishQueryEvent(ctx, &routing.QueryEvent{
				Type:      routing.PeerResponse,
				ID:        p,
				Responses: peers,
			})

			return peers, err
		},
		func() bool { return false },
	)

	if err != nil {
		return nil, err
	}

	if ctx.Err() == nil && lookupRes.completed {
		// tracking lookup results for network size estimator
		if err = dht.nsEstimator.Track(key, lookupRes.peers); err != nil {
			logger.Warnf("network size estimator track peers: %s", err)
		}
		// refresh the cpl for this key as the query was successful
		dht.routingTable.ResetCplRefreshedAtForID(kb.ConvertKey(key), time.Now())
	}

	return lookupRes.peers, ctx.Err()
}

// Function to find all peers with common prefix length >= minCPL with key
func (dht *IpfsDHT) GetPeersWithCPL(ctx context.Context, key string, minCPL int) ([]peer.ID, error) {
	keyIDString := fmt.Sprintf("%x", []byte(kb.ConvertKey(key)))
	set, err := dht.GetClosestPeers(ctx, key)
	if err != nil {
		return nil, err
	}
	fmt.Println("Get peers with CPL", minCPL, "for", keyIDString)
	fmt.Println("From first query:", len(set), "peers")
	cpl := minCommonPrefixLength(set, key)
	fmt.Println("From first query: cpl = ", cpl)
	var rt *kb.RoutingTable
	if cpl >= minCPL {
		rt, err = kb.NewRoutingTable(20, kb.ConvertKey(key), time.Minute, dht.host.Peerstore(), time.Minute, nil)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}
	for cpl >= minCPL {
		// Construct a random peerid to lookup, which has common prefix length EXACTLY cpl with key
		var queryPeerID peer.ID
		if cpl <= 15 {
			queryPeerID, err = rt.GenRandPeerID(uint(cpl))
			if err != nil {
				return nil, err
			}
			fmt.Printf("CPL: %d, Generated peerid: %x\n", cpl, kb.ConvertPeerID(queryPeerID))
			newSet, err := dht.GetPeersWithCPL(ctx, string(queryPeerID), cpl+1)
			if err != nil {
				return nil, err
			}
			set = append(set, newSet...)
			cpl -= 1
		} else {
			queryPeerID, err = rt.GenRandPeerID(15)
			if err != nil {
				return nil, err
			}
			fmt.Printf("CPL: %d, Generated peerid: %x\n", cpl, kb.ConvertPeerID(queryPeerID))
			newSet, err := dht.GetClosestPeers(ctx, string(queryPeerID))
			if err != nil {
				return nil, err
			}
			set = append(set, newSet...)
			cpl = minCommonPrefixLength(set, key)
		}

	}
	// Keep only those with required common prefix length
	truncSet := make([]peer.ID, 0, len(set))
	for _, id := range set {
		if kb.CommonPrefixLen(kb.ConvertPeerID(id), kb.ConvertKey(key)) >= minCPL {
			truncSet = append(truncSet, id)
		}
	}
	// Sort by distance before returning
	sortedSet := kb.SortClosestPeers(truncSet, kb.ConvertKey(key))
	return sortedSet, nil
}

// func (dht *IpfsDHT) GetPeersUptoDistance(ctx context.Context, key string, distance string) ([]peer.ID, error) {

// }

func minCommonPrefixLength(keys []peer.ID, target string) int {
	minCPL := 256
	targetHash := kb.ConvertKey(target)
	for _, key := range keys {
		cpl := kb.CommonPrefixLen(kb.ConvertPeerID(key), targetHash)
		if cpl < minCPL {
			minCPL = cpl
		}
	}
	return minCPL
}
