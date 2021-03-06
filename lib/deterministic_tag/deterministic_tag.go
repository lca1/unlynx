package libunlynxdetertag

import (
	"sync"

	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
)

// DeterministicTagSequence performs the second step in the distributed deterministic tagging process (cycle round) on a ciphervector.
func DeterministicTagSequence(cv libunlynx.CipherVector, private, secretContrib kyber.Scalar) libunlynx.CipherVector {
	cvNew := libunlynx.NewCipherVector(len(cv))

	var wg sync.WaitGroup

	for i := 0; i < len(cv); i = i + libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(cv)); j++ {
				(*cvNew)[i+j] = DeterministicTag(cv[i+j], private, secretContrib)
			}
		}(i)

	}
	wg.Wait()

	return *cvNew
}

// DeterministicTag the second step in the distributed deterministic tagging process (the cycle round) on a ciphertext.
func DeterministicTag(ct libunlynx.CipherText, private, secretContrib kyber.Scalar) libunlynx.CipherText {
	//ct(K,C) = (C1i-1, C2i-2)
	//ctNew(K,C) = (C1i,C2i)
	ctNew := libunlynx.NewCipherText()

	//secretContrib = si
	//ct.K = C1i-1
	//C1i = si * C1i-1
	ctNew.K = libunlynx.SuiTe.Point().Mul(secretContrib, ct.K)

	//private = ki
	//contrib = C1i-1*ki
	contrib := libunlynx.SuiTe.Point().Mul(private, ct.K)

	//C2i = si * (C2i-1 - contrib)
	ctNew.C = libunlynx.SuiTe.Point().Sub(ct.C, contrib)
	ctNew.C = libunlynx.SuiTe.Point().Mul(secretContrib, ctNew.C)

	return *ctNew
}

// Representation
//______________________________________________________________________________________________________________________

// CipherVectorToDeterministicTag creates a tag (grouping key) from a cipher vector (aggregation of *.C string representation of all the ciphertexts that are in the ciphervector)
func CipherVectorToDeterministicTag(vBef libunlynx.CipherVector, privKey, secContrib kyber.Scalar, K kyber.Point, proofs bool) (libunlynx.GroupingKey, *PublishedDDTCreationListProof, error) {
	vAft := DeterministicTagSequence(vBef, privKey, secContrib)

	var pdclp PublishedDDTCreationListProof
	if proofs {
		var err error
		pdclp, err = DeterministicTagCrListProofCreation(vBef, vAft, K, privKey, secContrib)
		if err != nil {
			return libunlynx.GroupingKey(""), nil, err
		}
	}

	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(vAft))
	for j, c := range vAft {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	return deterministicGroupAttributes.Key(), &pdclp, nil
}
