package libunlynxaggr

import (
	"math"
	"sync"

	"github.com/ldsec/unlynx/lib"
)

// PublishedAggregationProof contains all the information for one aggregation proof
type PublishedAggregationProof struct {
	Data              libunlynx.CipherVector
	AggregationResult libunlynx.CipherText
}

// PublishedAggregationProofBytes is the 'bytes' equivalent of PublishedAggregationProof
type PublishedAggregationProofBytes struct {
	Data              []byte
	DataLen           int64
	AggregationResult []byte
}

// PublishedAggregationListProof contains a list of aggregation proofs
type PublishedAggregationListProof struct {
	List []PublishedAggregationProof
}

// PublishedAggregationListProofBytes is the 'bytes' equivalent of PublishedAggregationListProof
type PublishedAggregationListProofBytes struct {
	List []PublishedAggregationProofBytes
}

// AGGREGATION proofs
//______________________________________________________________________________________________________________________

// AggregationProofCreation creates a proof for aggregation
func AggregationProofCreation(data libunlynx.CipherVector, aggregationResult libunlynx.CipherText) PublishedAggregationProof {
	return PublishedAggregationProof{Data: data, AggregationResult: aggregationResult}
}

// AggregationListProofCreation creates multiple proofs for aggregation
func AggregationListProofCreation(data []libunlynx.CipherVector, aggregationResults []libunlynx.CipherText) PublishedAggregationListProof {
	papList := PublishedAggregationListProof{}
	papList.List = make([]PublishedAggregationProof, len(data))

	var wg sync.WaitGroup
	for i := 0; i < len(data); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(data); j++ {
				pap := AggregationProofCreation(data[i+j], aggregationResults[i+j])
				papList.List[i+j] = pap
			}
		}(i)
	}
	wg.Wait()

	return papList
}

// AggregationProofVerification verifies an aggregation proof
func AggregationProofVerification(pap PublishedAggregationProof) bool {
	expected := pap.Data.Acum()
	return expected.Equal(&pap.AggregationResult)
}

// AggregationListProofVerification verifies multiple aggregation proofs
func AggregationListProofVerification(palp PublishedAggregationListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(palp.List))))
	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToVerify; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < nbrProofsToVerify; j++ {
				results[i+j] = AggregationProofVerification(palp.List[i+j])
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

// ToBytes converts PublishedAggregationProof to bytes
func (pap *PublishedAggregationProof) ToBytes() (PublishedAggregationProofBytes, error) {
	papb := PublishedAggregationProofBytes{}
	var dataLen int
	var err error
	papb.Data, dataLen, err = pap.Data.ToBytes()
	if err != nil {
		return PublishedAggregationProofBytes{}, err
	}

	papb.DataLen = int64(dataLen)
	papb.AggregationResult, err = pap.AggregationResult.ToBytes()
	if err != nil {
		return PublishedAggregationProofBytes{}, err
	}

	return papb, nil
}

// FromBytes converts back bytes to PublishedAggregationProof
func (pap *PublishedAggregationProof) FromBytes(papb PublishedAggregationProofBytes) error {
	if err := pap.AggregationResult.FromBytes(papb.AggregationResult); err != nil {
		return err
	}
	err := pap.Data.FromBytes(papb.Data, int(papb.DataLen))
	if err != nil {
		return err
	}
	return nil
}

// ToBytes converts PublishedAggregationListProof to bytes
func (palp *PublishedAggregationListProof) ToBytes() (PublishedAggregationListProofBytes, error) {
	palpb := PublishedAggregationListProofBytes{}

	palpb.List = make([]PublishedAggregationProofBytes, len(palp.List))

	wg := libunlynx.StartParallelize(uint(len(palpb.List)))
	for i, pap := range palp.List {
		go func(index int, pap PublishedAggregationProof) {
			var err error
			palpb.List[index], err = pap.ToBytes()
			wg.Done(err)
		}(i, pap)
	}
	if err := libunlynx.EndParallelize(wg); err != nil {
		return PublishedAggregationListProofBytes{}, err
	}

	return palpb, nil
}

// FromBytes converts bytes back to PublishedAggregationListProof
func (palp *PublishedAggregationListProof) FromBytes(palpb PublishedAggregationListProofBytes) error {
	palp.List = make([]PublishedAggregationProof, len(palpb.List))

	var err error
	wg := libunlynx.StartParallelize(uint(len(palpb.List)))
	for i, papb := range palpb.List {
		go func(index int, papb PublishedAggregationProofBytes) {
			pap := PublishedAggregationProof{}
			err := pap.FromBytes(papb)
			defer wg.Done(err)

			palp.List[index] = pap
		}(i, papb)
	}
	libunlynx.EndParallelize(wg)

	if err != nil {
		return err
	}
	return nil
}
