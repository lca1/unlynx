package libunlynxshuffle

import (
	"math"
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	shuffleKyber "github.com/dedis/kyber/shuffle"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
)

// Structs
//______________________________________________________________________________________________________________________

// PublishedShufflingProof contains all infos about proofs for shuffling
type PublishedShufflingProof struct {
	OriginalList []libunlynx.CipherVector
	ShuffledList []libunlynx.CipherVector
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// PublishedShufflingProofBytes is the 'bytes' equivalent of PublishedShufflingProof
type PublishedShufflingProofBytes struct {
	OriginalList       *[]byte
	OriginalListLength *[]byte
	ShuffledList       *[]byte
	ShuffledListLength *[]byte
	G                  *[]byte
	H                  *[]byte
	HashProof          []byte
}

// PublishedShufflingListProof contains a list of shuffling proofs
type PublishedShufflingListProof struct {
	Pslp []PublishedShufflingProof
}

// SHUFFLE proofs
//______________________________________________________________________________________________________________________

// ShuffleProofCreation creates a shuffle proof
func ShuffleProofCreation(originalList, shuffledList []libunlynx.CipherVector, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) PublishedShufflingProof {
	e := originalList[0].CipherVectorTag(h)
	k := len(originalList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

	wg1 := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		go func(inputList, outputList []libunlynx.CipherVector, i int) {
			defer (*wg1).Done()
			compressCipherVectorMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
		}(originalList, shuffledList, i)
	}
	libunlynx.EndParallelize(wg1)

	betaCompressed := compressBeta(beta, e)

	rand := libunlynx.SuiTe.RandomStream()

	// do k-shuffle of ElGamal on the (Xhat,Yhat) and check it
	k = len(Xhat)
	if k != len(Yhat) {
		panic("X,Y vectors have inconsistent lengths")
	}
	ps := shuffleKyber.PairShuffle{}
	ps.Init(libunlynx.SuiTe, k)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, nil, h, betaCompressed, Xhat, Yhat, rand, ctx)
	}

	prf, err := proof.HashProve(libunlynx.SuiTe, "PairShuffle", prover)
	if err != nil {
		panic("Shuffle proof failed: " + err.Error())
	}
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}
}

// ShuffleListProofCreation generates a list of shuffle proofs
func ShuffleListProofCreation(originalList, shuffledList [][]libunlynx.CipherVector, gList, hList []kyber.Point, betaList [][][]kyber.Scalar, piList [][]int) PublishedShufflingListProof {
	nbrProofsToCreate := len(originalList)

	listProofs := PublishedShufflingListProof{}
	listProofs.Pslp = make([]PublishedShufflingProof, nbrProofsToCreate)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToCreate; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, originalList, shuffledList [][]libunlynx.CipherVector, g, h []kyber.Point, beta [][][]kyber.Scalar, pi [][]int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < nbrProofsToCreate); j++ {
				listProofs.Pslp[i+j] = ShuffleProofCreation(originalList[i+j], shuffledList[i+j], g[i+j], h[i+j], beta[i+j], pi[i+j])
			}
			defer wg.Done()
		}(i, originalList, shuffledList, gList, hList, betaList, piList)
	}
	wg.Wait()

	return listProofs
}

// ShuffleProofVerification verifies a shuffle proof
func ShuffleProofVerification(psp PublishedShufflingProof, seed kyber.Point) bool {
	e := psp.OriginalList[0].CipherVectorTag(seed)
	var x, y, xbar, ybar []kyber.Point

	wg := libunlynx.StartParallelize(2)
	go func() {
		x, y = compressListCipherVector(psp.OriginalList, e)
		defer (*wg).Done()
	}()
	go func() {
		xbar, ybar = compressListCipherVector(psp.ShuffledList, e)
		defer (*wg).Done()
	}()

	libunlynx.EndParallelize(wg)

	verifier := shuffleKyber.Verifier(libunlynx.SuiTe, psp.G, psp.H, x, y, xbar, ybar)
	err := proof.HashVerify(libunlynx.SuiTe, "PairShuffle", verifier, psp.HashProof)
	if err != nil {
		log.LLvl1(err)
		log.LLvl1("-----------verify failed (with XharBar)")
		return false
	}

	return true
}

// ShuffleListProofVerification verifies a list of shuffle proofs
func ShuffleListProofVerification(listProofs PublishedShufflingListProof, seed kyber.Point, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(listProofs.Pslp))))

	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedShufflingProof) {
			defer wg.Done()
			results[i] = ShuffleProofVerification(v, seed)
		}(i, listProofs.Pslp[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// Compress
//______________________________________________________________________________________________________________________

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector libunlynx.CipherVector, e []kyber.Scalar) libunlynx.CipherText {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		panic("e is not the right size!")
	}

	ciphertext := *libunlynx.NewCipherText()
	for i := 0; i < k; i++ {
		aux := libunlynx.NewCipherText()
		aux.MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *aux)
	}
	return ciphertext
}

// compressListCipherVector applies shuffling compression to a list of ciphervectors
func compressListCipherVector(processResponses []libunlynx.CipherVector, e []kyber.Scalar) ([]kyber.Point, []kyber.Point) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	wg := libunlynx.StartParallelize(len(processResponses))
	for i, v := range processResponses {
		go func(i int, v libunlynx.CipherVector) {
			tmp := compressCipherVector(v, e)
			xK[i] = tmp.K
			xC[i] = tmp.C
			defer wg.Done()
		}(i, v)
	}

	libunlynx.EndParallelize(wg)
	return xK, xC
}

// compressCipherVectorMultiple applies shuffling compression to 2 ciphervectors corresponding to the input and the output of shuffling
func compressCipherVectorMultiple(inputList, outputList []libunlynx.CipherVector, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) {
	wg := libunlynx.StartParallelize(2)
	go func() {
		defer wg.Done()
		tmp := compressCipherVector(inputList[i], e)
		Xhat[i] = tmp.K
		Yhat[i] = tmp.C
	}()
	go func() {
		defer wg.Done()
		tmpBar := compressCipherVector(outputList[i], e)
		XhatBar[i] = tmpBar.K
		YhatBar[i] = tmpBar.C
	}()
	libunlynx.EndParallelize(wg)
}

// compressBeta applies shuffling compression to a matrix of scalars
func compressBeta(beta [][]kyber.Scalar, e []kyber.Scalar) []kyber.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]kyber.Scalar, k)
	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = libunlynx.SuiTe.Scalar().Zero()

		go func(i int) {
			defer wg.Done()
			for j := 0; j < NQ; j++ {
				tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)

	return betaCompressed
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes transforms PublishedShufflingProof to bytes
func (psp *PublishedShufflingProof) ToBytes() PublishedShufflingProofBytes {
	pspb := PublishedShufflingProofBytes{}

	wg := libunlynx.StartParallelize(3)

	// convert OriginalList
	mutex1 := sync.Mutex{}
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength := libunlynx.ArrayCipherVectorToBytes(data)

		mutex1.Lock()
		pspb.OriginalList = &tmp
		pspb.OriginalListLength = &tmpLength
		mutex1.Unlock()
	}(psp.OriginalList)

	// convert ShuffledList
	mutex2 := sync.Mutex{}
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength := libunlynx.ArrayCipherVectorToBytes(data)

		mutex2.Lock()
		pspb.ShuffledList = &tmp
		pspb.ShuffledListLength = &tmpLength
		mutex2.Unlock()
	}(psp.ShuffledList)

	// convert 'the rest'
	go func(G, H kyber.Point, HashProof []byte) {
		defer wg.Done()

		tmpGBytes := libunlynx.AbstractPointsToBytes([]kyber.Point{G})
		pspb.G = &tmpGBytes
		tmpHBytes := libunlynx.AbstractPointsToBytes([]kyber.Point{H})
		pspb.H = &tmpHBytes

		pspb.HashProof = psp.HashProof
	}(psp.G, psp.H, psp.HashProof)

	libunlynx.EndParallelize(wg)

	return pspb
}

// FromBytes transforms bytes back to PublishedShufflingProof
func (psp *PublishedShufflingProof) FromBytes(pspb PublishedShufflingProofBytes) {
	psp.OriginalList = libunlynx.FromBytesToArrayCipherVector(*pspb.OriginalList, *pspb.OriginalListLength)
	psp.ShuffledList = libunlynx.FromBytesToArrayCipherVector(*pspb.ShuffledList, *pspb.ShuffledListLength)
	psp.G = libunlynx.FromBytesToAbstractPoints(*pspb.G)[0]
	psp.H = libunlynx.FromBytesToAbstractPoints(*pspb.H)[0]
	psp.HashProof = pspb.HashProof
}