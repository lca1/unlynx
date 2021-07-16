package libunlynxkeyswitch

import (
	"fmt"
	"math"
	"sync"

	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/onet/v3/log"
)

// Structs
//______________________________________________________________________________________________________________________

// PublishedKSProof contains all infos about proofs for key switching
type PublishedKSProof struct {
	Proof []byte
	K     kyber.Point
	ViB   kyber.Point
	Ks2   kyber.Point
	RbNeg kyber.Point
	Q     kyber.Point
}

// PublishedKSProofBytes is the 'bytes' equivalent of PublishedKSProof
type PublishedKSProofBytes struct {
	Proof         []byte
	KVibKs2RbNegQ []byte
}

// PublishedKSListProof is a list of PublishedKSProof
type PublishedKSListProof struct {
	List []PublishedKSProof
}

// PublishedKSListProofBytes is the 'bytes' equivalent of PublishedKSListProof
type PublishedKSListProofBytes struct {
	List []PublishedKSProofBytes
}

// KEY SWITCH proofs
//______________________________________________________________________________________________________________________

func createPredicateKeySwitch() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("viB", "vi", "B")
	log2 := proof.Rep("K", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("ks2", "k", "rBNeg", "vi", "Q")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	predicate = proof.And(and)

	return
}

// KeySwitchProofCreation creates a key switch proof for one ciphertext
func KeySwitchProofCreation(K, Q kyber.Point, k kyber.Scalar, viB, ks2, rBNeg kyber.Point, vi kyber.Scalar) (PublishedKSProof, error) {
	predicate := createPredicateKeySwitch()
	sval := map[string]kyber.Scalar{"vi": vi, "k": k}
	pval := map[string]kyber.Point{"K": K, "viB": viB, "ks2": ks2, "rBNeg": rBNeg, "Q": Q}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	proofKS, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		return PublishedKSProof{}, fmt.Errorf("---------prover: %v", err)
	}

	return PublishedKSProof{Proof: proofKS, K: K, ViB: viB, Ks2: ks2, RbNeg: rBNeg, Q: Q}, nil
}

// KeySwitchListProofCreation creates a list of key switch proofs (multiple ciphertexts)
func KeySwitchListProofCreation(K, Q kyber.Point, k kyber.Scalar, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) (PublishedKSListProof, error) {
	viBs := make([]kyber.Point, len(vis))

	var wg1 sync.WaitGroup
	for i := 0; i < len(viBs); i += libunlynx.VPARALLELIZE {
		wg1.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(viBs)); j++ {
				viBs[i+j] = libunlynx.SuiTe.Point().Mul(vis[i+j], libunlynx.SuiTe.Point().Base())
			}
			defer wg1.Done()
		}(i)

	}
	wg1.Wait()

	plop := PublishedKSListProof{}
	plop.List = make([]PublishedKSProof, len(viBs))

	var err error
	mutex := sync.Mutex{}
	var wg2 sync.WaitGroup
	for i := 0; i < len(viBs); i += libunlynx.VPARALLELIZE {
		wg2.Add(1)
		go func(i int, Q kyber.Point, k kyber.Scalar) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(viBs)); j++ {
				proofAux, tmpErr := KeySwitchProofCreation(K, Q, k, viBs[i+j], ks2s[i+j], rBNegs[i+j], vis[i+j])
				if tmpErr != nil {
					mutex.Lock()
					err = tmpErr
					mutex.Unlock()
					return
				}
				plop.List[i+j] = proofAux
			}
			defer wg2.Done()
		}(i, Q, k)

	}
	wg2.Wait()

	if err != nil {
		return PublishedKSListProof{}, err
	}

	return plop, nil
}

// KeySwitchProofVerification verifies a key switch proof for one ciphertext
func KeySwitchProofVerification(pop PublishedKSProof) bool {
	predicate := createPredicateKeySwitch()
	pval := map[string]kyber.Point{"K": pop.K, "viB": pop.ViB, "ks2": pop.Ks2, "rBNeg": pop.RbNeg, "Q": pop.Q}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)

	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, pop.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// KeySwitchListProofVerification verifies a list of key switch proofs, if one is wrong, returns false
func KeySwitchListProofVerification(pkslp PublishedKSListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pkslp.List))))
	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToVerify; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < nbrProofsToVerify; j++ {
				results[i+j] = KeySwitchProofVerification(pkslp.List[i+j])
			}
		}(i)
	}
	wg.Wait()

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts PublishedKSProof to bytes
func (pksp *PublishedKSProof) ToBytes() (PublishedKSProofBytes, error) {
	popb := PublishedKSProofBytes{}
	popb.Proof = pksp.Proof
	data, err := libunlynx.AbstractPointsToBytes([]kyber.Point{pksp.K, pksp.ViB, pksp.Ks2, pksp.RbNeg, pksp.Q})
	if err != nil {
		return PublishedKSProofBytes{}, err
	}
	popb.KVibKs2RbNegQ = data
	return popb, nil
}

// FromBytes converts back bytes to PublishedKSProof
func (pksp *PublishedKSProof) FromBytes(pkspb PublishedKSProofBytes) error {
	pksp.Proof = pkspb.Proof
	data, err := libunlynx.FromBytesToAbstractPoints(pkspb.KVibKs2RbNegQ)
	if err != nil {
		return err
	}
	KVibKs2RbnegQ := data
	pksp.K = KVibKs2RbnegQ[0]
	pksp.ViB = KVibKs2RbnegQ[1]
	pksp.Ks2 = KVibKs2RbnegQ[2]
	pksp.RbNeg = KVibKs2RbnegQ[3]
	pksp.Q = KVibKs2RbnegQ[4]

	return nil
}

// ToBytes converts PublishedKSListProof to bytes
func (pkslp *PublishedKSListProof) ToBytes() (PublishedKSListProofBytes, error) {
	pkslpb := PublishedKSListProofBytes{}

	prsB := make([]PublishedKSProofBytes, len(pkslp.List))

	wg := libunlynx.StartParallelize(uint(len(pkslp.List)))
	for i, pksp := range pkslp.List {
		go func(index int, pksp PublishedKSProof) {
			data, err := pksp.ToBytes()
			defer wg.Done(err)

			prsB[index] = data
		}(i, pksp)
	}
	if err := libunlynx.EndParallelize(wg); err != nil {
		return PublishedKSListProofBytes{}, err
	}

	pkslpb.List = prsB
	return pkslpb, nil
}

// FromBytes converts bytes back to PublishedKSListProof
func (pkslp *PublishedKSListProof) FromBytes(pkslpb PublishedKSListProofBytes) error {
	prs := make([]PublishedKSProof, len(pkslpb.List))
	wg := libunlynx.StartParallelize(uint(len(pkslpb.List)))
	for i, pkspb := range pkslpb.List {
		go func(index int, pkspb PublishedKSProofBytes) {
			tmp := PublishedKSProof{}
			err := tmp.FromBytes(pkspb)
			defer wg.Done(err)

			prs[index] = tmp
		}(i, pkspb)
	}
	if err := libunlynx.EndParallelize(wg); err != nil {
		return err
	}
	pkslp.List = prs

	return nil
}
