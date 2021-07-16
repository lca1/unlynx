package libunlynxshuffle

import (
	"crypto/cipher"
	"math/big"
	"os"
	"sync"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/tools"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3/log"
)

// ShuffleSequence applies shuffling to a ciphervector
func ShuffleSequence(inputList []libunlynx.CipherVector, g, h kyber.Point, precomputed []CipherVectorScalar) ([]libunlynx.CipherVector, []int, [][]kyber.Scalar) {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	// number of elgamal pairs
	NQ := len(inputList[0])
	k := len(inputList) // number of clients

	rand := libunlynx.SuiTe.RandomStream()
	// Pick a fresh (or precomputed) ElGamal blinding factor for each pair
	beta := make([][]kyber.Scalar, k)
	precomputedPoints := make([]libunlynx.CipherVector, k)
	for i := 0; i < k; i++ {
		if precomputed == nil {
			beta[i] = libunlynx.RandomScalarSlice(NQ)
		} else {
			randInt := random.Int(big.NewInt(int64(maxInt)), rand)

			indice := int(randInt.Int64() % int64(len(precomputed)))
			beta[i] = precomputed[indice].S[0:NQ] //if beta file is bigger than query line responses
			precomputedPoints[i] = precomputed[indice].CipherV[0:NQ]
		}

	}

	// Pick a random permutation
	pi := libunlynx.RandomPermutation(k)

	outputList := make([]libunlynx.CipherVector, k)

	wg := libunlynx.StartParallelize(uint(k))
	for i := 0; i < k; i++ {
		go func(outputList []libunlynx.CipherVector, i int) {
			shuffle(pi, i, inputList, outputList, NQ, beta, precomputedPoints, g, h)
			wg.Done(nil)
		}(outputList, i)
	}
	libunlynx.EndParallelize(wg)

	return outputList, pi, beta
}

// shuffle applies shuffling and rerandomization
func shuffle(pi []int, i int, inputList, outputList []libunlynx.CipherVector, NQ int, beta [][]kyber.Scalar, precomputedPoints []libunlynx.CipherVector, g, h kyber.Point) {
	index := pi[i]
	outputList[i] = *libunlynx.NewCipherVector(NQ)
	wg := libunlynx.StartParallelize(uint(NQ))
	for j := 0; j < NQ; j++ {
		var b kyber.Scalar
		var ct libunlynx.CipherText
		if len(precomputedPoints[0]) == 0 {
			b = beta[index][j]
		} else {
			ct = precomputedPoints[index][j]
		}
		go func(j int) {
			outputList[i][j] = rerandomize(inputList[index], b, b, ct, g, h, j)
			wg.Done(nil)
		}(j)
	}
	libunlynx.EndParallelize(wg)
}

// rerandomize rerandomizes an element in a ciphervector at position j, following the Neff Shuffling algorithm
func rerandomize(cv libunlynx.CipherVector, a, b kyber.Scalar, cipher libunlynx.CipherText, g, h kyber.Point, j int) libunlynx.CipherText {
	ct := libunlynx.NewCipherText()
	var point1, point2 kyber.Point

	if cipher.C == nil {
		//no precomputed value
		point1 = libunlynx.SuiTe.Point().Mul(a, g)
		point2 = libunlynx.SuiTe.Point().Mul(b, h)
	} else {
		point1 = cipher.K
		point2 = cipher.C
	}

	ct.K = libunlynx.SuiTe.Point().Add(cv[j].K, point1)
	ct.C = libunlynx.SuiTe.Point().Add(cv[j].C, point2)
	return *ct
}

// Precomputation
//______________________________________________________________________________________________________________________

// CreatePrecomputedRandomize creates precomputed values for shuffling using public key and size parameters
func CreatePrecomputedRandomize(g, h kyber.Point, rand cipher.Stream, lineSize, nbrLines int) []CipherVectorScalar {
	result := make([]CipherVectorScalar, nbrLines)
	wg := libunlynx.StartParallelize(uint(len(result)))
	var mutex sync.Mutex
	for i := range result {
		result[i].CipherV = make(libunlynx.CipherVector, lineSize)
		result[i].S = make([]kyber.Scalar, lineSize)

		go func(i int) {
			for w := range result[i].CipherV {
				mutex.Lock()
				scalar := libunlynx.SuiTe.Scalar().Pick(rand)
				mutex.Unlock()

				result[i].S[w] = scalar
				result[i].CipherV[w].K = libunlynx.SuiTe.Point().Mul(scalar, g)
				result[i].CipherV[w].C = libunlynx.SuiTe.Point().Mul(scalar, h)
			}

			wg.Done(nil)
		}(i)
	}
	libunlynx.EndParallelize(wg)
	return result
}

// PrecomputeForShuffling precomputes data to be used in the shuffling protocol (to make it faster) and saves it in a .gob file
func PrecomputeForShuffling(serverName, gobFile string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) ([]CipherVectorScalar, error) {
	log.Lvl1(serverName, " precomputes for shuffling")
	scalarBytes, err := surveySecret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	precomputeShuffle := CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), collectiveKey, libunlynx.SuiTe.XOF(scalarBytes), lineSize*2, 10)

	encoded, err := EncodeCipherVectorScalar(precomputeShuffle)
	if err != nil {
		return nil, err
	}
	err = libunlynxtools.WriteToGobFile(gobFile, encoded)
	if err != nil {
		return nil, err
	}

	return precomputeShuffle, nil
}

// PrecomputationWritingForShuffling reads the precomputation data from  .gob file if it already exists or generates a new one
func PrecomputationWritingForShuffling(appFlag bool, gobFile, serverName string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) ([]CipherVectorScalar, error) {
	log.Lvl1(serverName, " precomputes for shuffling")
	var precomputeShuffle []CipherVectorScalar
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {
			precomputeShuffle, err = PrecomputeForShuffling(serverName, gobFile, surveySecret, collectiveKey, lineSize)
			if err != nil {
				return nil, err
			}
		} else {
			var encoded []CipherVectorScalarBytes
			err := libunlynxtools.ReadFromGobFile(gobFile, &encoded)
			if err != nil {
				return nil, err
			}

			precomputeShuffle, err = DecodeCipherVectorScalar(encoded)
			if err != nil {
				return nil, err
			}
		}
	} else {
		scalarBytes, err := surveySecret.MarshalBinary()
		if err != nil {
			return nil, err
		}
		precomputeShuffle = CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), collectiveKey, libunlynx.SuiTe.XOF(scalarBytes), lineSize*2, 10)
	}
	return precomputeShuffle, nil
}

// ReadPrecomputedFile reads the precomputation data from a .gob file
func ReadPrecomputedFile(fileName string) ([]CipherVectorScalar, error) {
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		var encoded []CipherVectorScalarBytes
		err := libunlynxtools.ReadFromGobFile(fileName, &encoded)
		if err != nil {
			return nil, err
		}
		return DecodeCipherVectorScalar(encoded)
	}
	return nil, nil
}
