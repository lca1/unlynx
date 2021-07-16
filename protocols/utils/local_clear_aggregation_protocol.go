// Package protocolsunlynxutils contains the LocalClearAggregation Protocol and its only purpose is to simulate aggregations done locally
// For example, it can be used to simulate a data provider doing some pre-processing on its data
package protocolsunlynxutils

import (
	"fmt"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/store"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"time"
)

// LocalClearAggregationProtocolName is the registered name for the local cleartext aggregation protocol.
const LocalClearAggregationProtocolName = "LocalClearAggregation"

func init() {
	_, err := onet.GlobalProtocolRegister(LocalClearAggregationProtocolName, NewLocalClearAggregationProtocol)
	log.ErrFatal(err, "Failed to register the <LocalClearAggregation> protocol:")
}

// Protocol
//______________________________________________________________________________________________________________________

// LocalClearAggregationProtocol is a struct holding the state of a protocol instance.
type LocalClearAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.DpClearResponse

	// Protocol state data
	TargetOfAggregation []libunlynx.DpClearResponse
}

// NewLocalClearAggregationProtocol is constructor of Proofs Verification protocol instances.
func NewLocalClearAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &LocalClearAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.DpClearResponse),
	}
	return pvp, nil
}

var finalResultClearAggr = make(chan []libunlynx.DpClearResponse, 1)

// Start is called at the root to start the execution of the local clear aggregation.
func (p *LocalClearAggregationProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), "started a local clear aggregation protocol")
	roundComput := libunlynx.StartTimer(p.Name() + "_LocalClearAggregation(START)")
	result := libunlynxstore.AddInClear(p.TargetOfAggregation)
	libunlynx.EndTimer(roundComput)
	finalResultClearAggr <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *LocalClearAggregationProtocol) Dispatch() error {
	defer p.Done()

	var finalResultMessage []libunlynx.DpClearResponse
	select {
	case finalResultMessage = <-finalResultClearAggr:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <finalResultMessage> on time")
	}

	p.FeedbackChannel <- finalResultMessage
	return nil
}
