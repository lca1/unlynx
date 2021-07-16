// The collective aggregation protocol collectively aggregates the local results of a query from all the servers.
// It uses a tree structure aggregation:
// 1. the root sends down an aggregation trigger message;
// 2. the leafs respond with their local result;
// 3. parent nodes aggregate the information from their children;
// 4. these nodes forward the aggregation result up the tree.

package protocolsunlynx

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/aggregation"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// CollectiveAggregationProtocolName is the registered name for the collective aggregation protocol.
const CollectiveAggregationProtocolName = "CollectiveAggregation"

// EMPTYKEY Const string to use as default key when use SimpleData array
const EMPTYKEY = ""

func init() {
	network.RegisterMessage(DataReferenceMessage{})
	network.RegisterMessage(ChildAggregatedDataMessage{})
	network.RegisterMessage(ChildAggregatedDataBytesMessage{})
	network.RegisterMessage(CADBLengthMessage{})
	_, err := onet.GlobalProtocolRegister(CollectiveAggregationProtocolName, NewCollectiveAggregationProtocol)
	log.ErrFatal(err, "Failed to register the <CollectiveAggregation> protocol:")

}

// Messages
//______________________________________________________________________________________________________________________

// CothorityAggregatedData is the collective aggregation result.
type CothorityAggregatedData struct {
	GroupedData map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// DataReferenceMessage message sent to trigger an aggregation protocol.
type DataReferenceMessage struct{}

// ChildAggregatedDataMessage contains one node's aggregated data.
type ChildAggregatedDataMessage struct {
	ChildData []libunlynx.FilteredResponseDet
}

// ChildAggregatedDataBytesMessage is ChildAggregatedDataMessage in bytes.
type ChildAggregatedDataBytesMessage struct {
	Data []byte
}

// CADBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type CADBLengthMessage struct {
	GacbLength int
	AabLength  int
	DtbLength  int
}

// Structs
//______________________________________________________________________________________________________________________

type dataReferenceStruct struct {
	*onet.TreeNode
	DataReferenceMessage
}

type childAggregatedDataBytesStruct struct {
	*onet.TreeNode
	ChildAggregatedDataBytesMessage
}

type cadmbLengthStruct struct {
	*onet.TreeNode
	CADBLengthMessage
}

// proofCollectiveAggregationFunction defines a function that does 'stuff' with the collective aggregation proofs
type proofCollectiveAggregationFunction func([]libunlynx.CipherVector, libunlynx.CipherVector) *libunlynxaggr.PublishedAggregationListProof

// Protocol
//______________________________________________________________________________________________________________________

// CollectiveAggregationProtocol performs an aggregation of the data held by every node in the cothority.
type CollectiveAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan CothorityAggregatedData

	// Protocol communication channels
	DataReferenceChannel chan dataReferenceStruct
	LengthNodeChannel    chan []cadmbLengthStruct
	ChildDataChannel     chan []childAggregatedDataBytesStruct

	// Protocol state data
	GroupedData *map[libunlynx.GroupingKey]libunlynx.FilteredResponse
	SimpleData  *[]libunlynx.CipherText

	// Proofs
	Proofs    bool
	ProofFunc proofCollectiveAggregationFunction // proof function for when we want to do something different with the proofs (e.g. insert in the blockchain)
	MapPIs    map[string]onet.ProtocolInstance   // protocol instances to be able to call protocols inside protocols (e.g. proof_collection_protocol)
}

// NewCollectiveAggregationProtocol initializes the protocol instance.
func NewCollectiveAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pap := &CollectiveAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan CothorityAggregatedData),
	}

	err := pap.RegisterChannel(&pap.DataReferenceChannel)
	if err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	err = pap.RegisterChannel(&pap.ChildDataChannel)
	if err != nil {
		return nil, fmt.Errorf("couldn't register child-data channel: %v", err)
	}

	if err := pap.RegisterChannel(&pap.LengthNodeChannel); err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	return pap, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *CollectiveAggregationProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), " started a Colective Aggregation Protocol")
	if err := p.SendToChildren(&DataReferenceMessage{}); err != nil {
		return fmt.Errorf("error sending <DataReferenceMessage>: %v", err)
	}
	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *CollectiveAggregationProtocol) Dispatch() error {
	defer p.Done()
	err := p.checkData()
	if err != nil {
		return err
	}

	// 1. Aggregation announcement phase
	if !p.IsRoot() {
		err := p.aggregationAnnouncementPhase()
		if err != nil {
			return err
		}
	}

	// 3. Proof generation (a) - before local aggregation
	cvMap := make(map[libunlynx.GroupingKey][]libunlynx.CipherVector)
	if p.Proofs {
		for k, v := range *p.GroupedData {
			frd := libunlynx.FilteredResponseDet{DetTagGroupBy: k, Fr: v}
			frd.FormatAggregationProofs(cvMap)
		}
	}

	// 2. Ascending aggregation phase
	aggregatedData, err := p.ascendingAggregationPhase(cvMap)
	if err != nil {
		return err
	}
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", len(*aggregatedData), "group(s) )")

	// 3. Proof generation (b) - after local aggregation
	if p.Proofs {
		data := make([]libunlynx.CipherVector, 0)
		dataRes := make(libunlynx.CipherVector, 0)
		for k, v := range cvMap {
			data = append(data, v...)
			dataRes = append(dataRes, (*aggregatedData)[k].AggregatingAttributes...)
		}
		p.ProofFunc(data, dataRes)
	}

	// 3. Result reporting
	if p.IsRoot() {
		p.FeedbackChannel <- CothorityAggregatedData{*aggregatedData}
	}
	return nil
}

// Announce forwarding down the tree.
func (p *CollectiveAggregationProtocol) aggregationAnnouncementPhase() error {
	select {
	case dataReferenceMessage := <-p.DataReferenceChannel:
		if err := p.SendToChildren(&dataReferenceMessage.DataReferenceMessage); err != nil {
			return fmt.Errorf("error sending <DataReferenceMessage>: %v", err)
		}
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <dataReferenceMessage> on time")
	}
	return nil
}

// Results pushing up the tree containing aggregation results.
func (p *CollectiveAggregationProtocol) ascendingAggregationPhase(cvMap map[libunlynx.GroupingKey][]libunlynx.CipherVector) (*map[libunlynx.GroupingKey]libunlynx.FilteredResponse, error) {
	roundTotComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(ascendingAggregation)")

	if !p.IsLeaf() {
		length := make([]cadmbLengthStruct, 0)
		for _, v := range <-p.LengthNodeChannel {
			length = append(length, v)
		}
		datas := make([]childAggregatedDataBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}

		for i, v := range length {
			childrenContribution := ChildAggregatedDataMessage{}
			err := childrenContribution.FromBytes(datas[i].Data, v.GacbLength, v.AabLength, v.DtbLength)
			if err != nil {
				return nil, err
			}

			roundComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Aggregation)")

			for _, aggr := range childrenContribution.ChildData {
				localAggr, ok := (*p.GroupedData)[aggr.DetTagGroupBy]

				if p.Proofs {
					aggr.FormatAggregationProofs(cvMap)
				}

				if ok {
					if len(localAggr.AggregatingAttributes) != len(aggr.Fr.AggregatingAttributes) {
						encZeros := make(libunlynx.CipherVector, int(math.Abs(float64(len(localAggr.AggregatingAttributes)-len(aggr.Fr.AggregatingAttributes)))))
						for e := range encZeros {
							encZeros[e] = *libunlynx.EncryptInt(p.Roster().Aggregate, 0)
						}
						if len(localAggr.AggregatingAttributes) > len(aggr.Fr.AggregatingAttributes) {
							aggr.Fr.AggregatingAttributes = append(aggr.Fr.AggregatingAttributes, encZeros...)
						} else {
							localAggr.AggregatingAttributes = append(localAggr.AggregatingAttributes, encZeros...)
						}
					}
					cv := libunlynx.NewCipherVector(len(localAggr.AggregatingAttributes))
					cv.Add(localAggr.AggregatingAttributes, aggr.Fr.AggregatingAttributes)

					localAggr.AggregatingAttributes = *cv
				} else {
					localAggr = aggr.Fr
				}
				(*p.GroupedData)[aggr.DetTagGroupBy] = localAggr
			}
			libunlynx.EndTimer(roundComput)

			roundProofs := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Proof-2ndPart)")

			libunlynx.EndTimer(roundProofs)
		}
	}

	libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {
		detAggrResponses := make([]libunlynx.FilteredResponseDet, len(*p.GroupedData))
		count := 0
		for i, v := range *p.GroupedData {
			detAggrResponses[count].DetTagGroupBy = i
			detAggrResponses[count].Fr = v
			count++
		}

		message := ChildAggregatedDataBytesMessage{}

		var gacbLength, aabLength, dtbLength int
		var err error

		message.Data, gacbLength, aabLength, dtbLength, err = (&ChildAggregatedDataMessage{detAggrResponses}).ToBytes()
		if err != nil {
			return nil, err
		}

		childrenContribution := ChildAggregatedDataMessage{}
		err = childrenContribution.FromBytes(message.Data, gacbLength, aabLength, dtbLength)
		if err != nil {
			return nil, err
		}

		if err := p.SendToParent(&CADBLengthMessage{gacbLength, aabLength, dtbLength}); err != nil {
			return nil, fmt.Errorf("error sending <CADBLengthMessage>: %v", err)
		}
		if err := p.SendToParent(&message); err != nil {
			return nil, fmt.Errorf("error sending <ChildAggregatedDataMessage>: %v", err)
		}
	}

	return p.GroupedData, nil
}

// Setup and return the data needed in the aggregation to a usable format
func (p *CollectiveAggregationProtocol) checkData() error {
	// If no data is passed to the collection protocol
	if p.GroupedData == nil && p.SimpleData == nil {
		return fmt.Errorf("no data reference is provided")
		// If both data entry points are used
	} else if p.GroupedData != nil && p.SimpleData != nil {
		return fmt.Errorf("two data references are given in the struct")
		// If we are using the GroupedData keep everything as is
	} else if p.GroupedData != nil {
		return nil
		// If we are using the SimpleData struct we must convert it to a GroupedData struct
	} else {
		result := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
		if len(*p.SimpleData) > 0 {
			result[EMPTYKEY] = libunlynx.FilteredResponse{
				AggregatingAttributes: make([]libunlynx.CipherText, len(*p.SimpleData)),
			}
			for i, v := range *p.SimpleData {
				result[EMPTYKEY].AggregatingAttributes[i] = v
			}
		}
		p.GroupedData = &result
		p.SimpleData = nil
		return nil
	}
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a ChildAggregatedDataMessage to a byte array
func (sm *ChildAggregatedDataMessage) ToBytes() ([]byte, int, int, int, error) {

	b := make([]byte, 0)
	bb := make([][]byte, len((*sm).ChildData))

	var gacbLength int
	var aabLength int
	var dtbLength int

	wg := libunlynx.StartParallelize(uint(len((*sm).ChildData)))
	var mutexCD sync.Mutex
	for i := range (*sm).ChildData {
		go func(i int) {
			mutexCD.Lock()
			data := (*sm).ChildData[i]
			mutexCD.Unlock()

			aux, gacbAux, aabAux, dtbAux, err := data.ToBytes()
			defer wg.Done(err)

			mutexCD.Lock()
			bb[i] = aux
			gacbLength = gacbAux
			aabLength = aabAux
			dtbLength = dtbAux
			mutexCD.Unlock()

		}(i)
	}
	if err := libunlynx.EndParallelize(wg); err != nil {
		return nil, 0, 0, 0, err
	}

	for _, el := range bb {
		b = append(b, el...)
	}
	return b, gacbLength, aabLength, dtbLength, nil
}

// FromBytes converts a byte array to a ChildAggregatedDataMessage. Note that you need to create the (empty) object beforehand.
func (sm *ChildAggregatedDataMessage) FromBytes(data []byte, gacbLength, aabLength, dtbLength int) error {
	cipherTextSize := libunlynx.CipherTextByteSize()
	elementLength := gacbLength*cipherTextSize + aabLength*cipherTextSize + dtbLength

	if elementLength != 0 && len(data) > 0 {
		var nbrChildData int
		nbrChildData = len(data) / elementLength

		(*sm).ChildData = make([]libunlynx.FilteredResponseDet, nbrChildData)

		wg := libunlynx.StartParallelize(uint(nbrChildData))
		for i := 0; i < nbrChildData; i++ {
			v := data[i*elementLength : i*elementLength+elementLength]
			go wg.Done((*sm).ChildData[i].FromBytes(v, gacbLength, aabLength, dtbLength))
		}
		if err := libunlynx.EndParallelize(wg); err != nil {
			return err
		}
	}
	return nil
}
