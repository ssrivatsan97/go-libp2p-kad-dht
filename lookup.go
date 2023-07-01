package dht

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"

	util "github.com/ipfs/go-ipfs-util"
	kb "github.com/libp2p/go-libp2p-kbucket"
)

type requestFn func(context.Context, string) ([]peer.ID, error)

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
		// currently disabled because we should not track peers from queries for only attacked CIDs. Instead use GatherNetsizeData() periodically to query random keys and update the netsize estimate
		// if err = dht.nsEstimator.Track(key, lookupRes.peers); err != nil {
		// 	logger.Warnf("network size estimator track peers: %s", err)
		// }
		// refresh the cpl for this key as the query was successful
		dht.routingTable.ResetCplRefreshedAtForID(kb.ConvertKey(key), time.Now())
	}

	return lookupRes.peers, ctx.Err()
}

// Function to find all peers with common prefix length >= minCPL with key
func (dht *IpfsDHT) GetPeersWithCPLGet(ctx context.Context, key string, minCPL int) ([]peer.ID, int, error) {
	return dht.GetPeersWithCPL(ctx, key, minCPL, dht.GetClosestPeers)
}

// Function to find all peers with common prefix length >= minCPL with key, and send a request to each found peer based on requestFn
func (dht *IpfsDHT) GetPeersWithCPL(ctx context.Context, key string, minCPL int, requestFn requestFn) ([]peer.ID, int, error) {
	// Input validation
	if minCPL < 0 {
		minCPL = 0
	}
	numLookups := 0
	set, err := requestFn(ctx, key)
	if err != nil {
		return nil, numLookups, err
	}
	numLookups += 1
	// fmt.Printf("Get peers with CPL %d  for %x\n", minCPL, []byte(kb.ConvertKey(key)))
	// fmt.Println("From first query:", len(set), "peers")
	cpl := minCommonPrefixLength(set, key)
	// fmt.Println("From first query: cpl = ", cpl)
	var rt *kb.RoutingTable
	if cpl >= minCPL {
		rt, err = kb.NewRoutingTable(20, kb.ConvertKey(key), time.Minute, dht.host.Peerstore(), time.Minute, nil)
		if err != nil {
			return nil, numLookups, err
		}
	}
	for cpl >= minCPL {
		// Construct a random peerid to lookup, which has common prefix length EXACTLY cpl with key
		var queryPeerID peer.ID
		if cpl <= 15 { // This condition is because I can only generate random peerid with common prefix length <= 15
			queryPeerID, err = rt.GenRandPeerID(uint(cpl))
			if err != nil {
				return nil, numLookups, err
			}
			// fmt.Printf("CPL: %d, Generated peerid: %x\n", cpl, kb.ConvertPeerID(queryPeerID))
			newSet, addLookups, err := dht.GetPeersWithCPL(ctx, string(queryPeerID), cpl+1, requestFn)
			if err != nil {
				return nil, numLookups, err
			}
			numLookups += addLookups
			set = append(set, newSet...)
			cpl -= 1
		} else {
			// The method may not remain correct if a single GetClosestPeers() request only returns
			// peers with a common prefix of 16 or more. Hopefully, this won't happen often as long as there are enough peers in the DHT.
			// At least, the function won't go into an infinite loop!
			queryPeerID = set[len(set)-1]
			// fmt.Printf("CPL: %d, Chosen peerid: %x\n", cpl, kb.ConvertPeerID(queryPeerID))
			newSet, err := requestFn(ctx, string(queryPeerID))
			if err != nil {
				return nil, numLookups, err
			}
			numLookups += 1
			set = append(set, newSet...)
			cpl -= 1 // This does not guarantee correctness, but prevents an infinite loop!
		}

	}
	// Remove duplicates and keep only those with required common prefix length
	setMap := make(map[peer.ID]struct{})
	truncSet := make([]peer.ID, 0, len(set))
	for _, id := range set {
		if _, ok := setMap[id]; !ok {
			if kb.CommonPrefixLen(kb.ConvertPeerID(id), kb.ConvertKey(key)) >= minCPL {
				setMap[id] = struct{}{}
				truncSet = append(truncSet, id)
			}
		}
	}
	// Sort by distance before returning
	sortedSet := kb.SortClosestPeers(truncSet, kb.ConvertKey(key))
	return sortedSet, numLookups, nil
	// Will probably be more efficient to truncate after sorting so that it could be done by a binary search
}

// Function to find all peers with distance up to maxDist from key.
// maxDist is a number between 0 to 2^256 - 1 and must be specified as a byte array.
// For example, if the distance is 2^230 - 1, it will be specified as
// [[0],[0],[0],[63],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255],[255]]
// This function is not optimal at this point, because it requests for all peers with common prefix length CPL with key
// such that distance < 2^(256-CPL). Thus, it could explore an additional part of the keyspace with up to 2^(256-CPL-1) keys.
// This inefficiency is because we are unable to query any chosen queryKey, but can only query peerids generated from GenRandPeerID()
// For now, it is recommended that you look for peers within distance where distance = 2^m - 1 for some m,
// and for that use GetPeersWithCPL(key, 256 - m) instead of GetPeersWithDistance.
func (dht *IpfsDHT) GetPeersWithDistance(ctx context.Context, key string, maxDist []byte, requestFn requestFn) ([]peer.ID, int, error) {
	minCPL := kb.CommonPrefixLen(maxDist, make([]byte, 32))
	set, numLookups, err := dht.GetPeersWithCPL(ctx, key, minCPL, requestFn)
	if err != nil {
		return nil, numLookups, err
	}
	// Keep only those with required distance
	// Dedeuplication is not necessary because GetPeersWithCPL() already does it
	truncSet := make([]peer.ID, 0, len(set))
	keyHash := kb.ConvertKey(key)
	maxDistHex := fmt.Sprintf("%x", maxDist)
	for _, id := range set {
		distHex := fmt.Sprintf("%x", util.XOR(keyHash, kb.ConvertPeerID(id)))
		if distHex <= maxDistHex {
			truncSet = append(truncSet, id)
		}
	}
	// Sort by distance before returning
	sortedSet := kb.SortClosestPeers(truncSet, kb.ConvertKey(key))
	return sortedSet, numLookups, nil
	// Will probably be more efficient to truncate after sorting so that it could be done by a binary search
}

func minCommonPrefixLength(peerids []peer.ID, target string) int {
	minCPL := 256
	targetHash := kb.ConvertKey(target)
	for _, pid := range peerids {
		cpl := kb.CommonPrefixLen(kb.ConvertPeerID(pid), targetHash)
		if cpl < minCPL {
			minCPL = cpl
		}
	}
	return minCPL
}

func maxDistance(peerids []peer.ID, target string) string {
	maxDist := "0000000000000000000000000000000000000000000000000000000000000000"
	targetHash := kb.ConvertKey(target)
	for _, pid := range peerids {
		dist := fmt.Sprintf("%x", util.XOR(targetHash, kb.ConvertPeerID(pid)))
		if dist > maxDist {
			maxDist = dist
		}
	}
	return maxDist
}
