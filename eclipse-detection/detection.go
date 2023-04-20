package detection

import (
	"math"

	"gonum.org/v1/gonum/stat/distuv"

	// XOR of byte slices
	kb "github.com/libp2p/go-libp2p-kbucket" // common prefix length of two IDs
)

type EclipseDetector struct {
	k         int
	idealDist []float64
	threshold float64
}

const (
	keySize          = 256
	defaultThreshold = 0.94 // hard-coded value based on the experiments
)

func New(k int) *EclipseDetector {
	det := &EclipseDetector{
		k:         k,
		idealDist: make([]float64, keySize),
		threshold: defaultThreshold,
	}
	for i := 0; i < keySize; i++ {
		det.idealDist[i] = math.Pow(0.5, float64(i+1))
	}
	return det
}

func (det *EclipseDetector) UpdateIdealDistFromNetsize(n int) []float64 {
	orderPmfs := make([][]float64, det.k)
	s := make([]float64, keySize)
	for i := 0; i < det.k; i++ {
		orderPmfs[i] = make([]float64, keySize)
		for x := 0; x < keySize; x++ {
			b := distuv.Binomial{
				N: float64(n),
				P: math.Pow(0.5, float64(x+1)),
			}
			s[x] += b.Prob(float64(i))
			if x == 0 {
				orderPmfs[i][x] = s[x]
			} else {
				orderPmfs[i][x] = s[x] - s[x-1]
			}
		}
	}
	avgPmf := make([]float64, keySize)
	for x := 0; x < keySize; x++ {
		for i := 0; i < det.k; i++ {
			avgPmf[x] += orderPmfs[i][x]
		}
		avgPmf[x] /= float64(det.k)
	}
	det.idealDist = avgPmf
	return avgPmf
}

func (det *EclipseDetector) UpdateThreshold(threshold float64) {
	det.threshold = threshold
}

func (det *EclipseDetector) GetThreshold() float64 {
	return det.threshold
}

func (det *EclipseDetector) ComputePrefixLenCounts(id []byte, closestIds [][]byte) []int {
	counts := make([]int, keySize)
	for _, cid := range closestIds {
		prefixLen := kb.CommonPrefixLen(id, cid)
		counts[prefixLen]++
	}
	return counts
}

func (det *EclipseDetector) ComputeKL(id []byte, closestIds [][]byte) float64 {
	return det.ComputeKLFromCounts(det.ComputePrefixLenCounts(id, closestIds))
}

func (det *EclipseDetector) ComputeKLFromCounts(prefixLenCounts []int) float64 {
	var kl float64
	for p := 0; p < keySize; p++ {
		if prefixLenCounts[p] > 0 {
			prob := float64(prefixLenCounts[p]) / float64(det.k)
			kl += prob * math.Log(prob/det.idealDist[p])
		}
	}
	return kl
}

// Return true if attack detected, false if no attack
func (det *EclipseDetector) DetectFromKL(kl float64) bool {
	return kl > det.threshold
}

func (det *EclipseDetector) DetectFromCounts(prefixLenCounts []int) bool {
	return det.ComputeKLFromCounts(prefixLenCounts) > det.threshold
}

func (det *EclipseDetector) Detect(id []byte, closestIds [][]byte) bool {
	return det.ComputeKL(id, closestIds) > det.threshold
}
