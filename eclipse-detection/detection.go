package detection

import (
	"math"

	"gonum.org/v1/gonum/stat/distuv"

	// XOR of byte slices
	kb "github.com/libp2p/go-libp2p-kbucket" // common prefix length of two IDs
)

type EclipseDetector struct {
	k            int
	idealDist    []float64
	l            int
	threshold    float64
	thresholdMap map[int]float64
}

const (
	keySize              = 256
	eps                  = 0.001
	thresholdMapInterval = 1000
)

func New(k int) *EclipseDetector {
	det := &EclipseDetector{
		k:         k,
		idealDist: make([]float64, keySize),
		l:         0,
		threshold: math.Inf(1), // by default, say there are no attacks
		thresholdMap: map[int]float64{
			1000:  1.7657010851723764,
			2000:  1.7817993072091078,
			3000:  1.5811957056268113,
			4000:  1.7254089336242442,
			5000:  1.2981035153460965,
			6000:  1.530734433661144,
			7000:  1.6282523015657908,
			8000:  1.7476952544539643,
			9000:  1.1713635267068827,
			10000: 1.5316765986059655,
			11000: 1.538657899641121,
			12000: 1.5740467141787955,
			13000: 1.6381675841972336,
			14000: 1.745077285059787,
			15000: 1.7181823662090514,
			16000: 1.7908064287069463,
			17000: 1.156022302500651,
			18000: 1.175734315398986,
			19000: 1.1542823194843208,
			20000: 1.2291546751913174,
			21000: 1.2923489041964578,
			22000: 1.3694039734028194,
			23000: 1.5137507072259009,
			24000: 1.5447567799609476,
			25000: 1.5577638653681902,
			26000: 1.60161784877906,
			27000: 1.654936423539085,
			28000: 1.641784494533182,
			29000: 1.655449897684465,
			30000: 1.6975670196217854,
			31000: 1.7405517002592936,
			32000: 1.7940663958943739,
			33000: 1.0413645834354617,
			34000: 1.0829225170056334,
			35000: 1.1511232009669132,
			36000: 1.1595493933661236,
			37000: 1.1455248288820432,
			38000: 1.1915813083443891,
			39000: 1.1900415398062867,
			40000: 1.1625857101864194,
			41000: 1.2920090068236707,
			42000: 1.2195293900441366,
			43000: 1.3396061759989502,
			44000: 1.3573602254948913,
			45000: 1.521389821971196,
			46000: 1.503108310847049,
			47000: 1.4571818841114597,
			48000: 1.528069407103029,
			49000: 1.5659135074742079,
		},
	}
	for i := 0; i < keySize; i++ {
		det.idealDist[i] = math.Pow(0.5, float64(i+1))
	}
	return det
}

func (det *EclipseDetector) UpdateL(l int) {
	det.l = l
}

func (det *EclipseDetector) UpdateLFromNetsize(n int) int {
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
	for x := 0; x < keySize; x++ {
		var avgPmfX float64
		for i := 0; i < det.k; i++ {
			avgPmfX += orderPmfs[i][x]
		}
		avgPmfX /= float64(det.k)
		if avgPmfX > eps {
			det.l = x
			return x
		}
	}
	return keySize
}

func (det *EclipseDetector) UpdateThreshold(threshold float64) {
	det.threshold = threshold
}

func (det *EclipseDetector) UpdateThresholdFromNetsize(n int) float64 {
	key := int(math.Round(float64(n)/float64(thresholdMapInterval))) * thresholdMapInterval
	t := det.thresholdMap[key]
	det.threshold = t
	return t
}

func (det *EclipseDetector) ComputePrefixLenCounts(id []byte, closestIds [][]byte) []int { // How are peerids represented?
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
	for p := det.l; p < keySize; p++ {
		if prefixLenCounts[p] > 0 {
			prob := float64(prefixLenCounts[p]) / float64(det.k)
			kl += prob * math.Log(prob/(det.idealDist[p]/det.idealDist[det.l-1]))
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
