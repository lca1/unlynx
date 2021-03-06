package protocolsunlynx

import (
	"fmt"
	"sync"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/deterministic_tag"
	"github.com/ldsec/unlynx/lib/shuffle"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// ShufflingPlusDDTProtocolName is the registered name for the shuffling + .
const ShufflingPlusDDTProtocolName = "ShufflingPlusDDTProtocol"

func init() {
	network.RegisterMessage(ShufflingPlusDDTMessage{})
	network.RegisterMessage(ShufflingPlusDDTBytesMessage{})
	network.RegisterMessage(ShufflingPlusDDTBytesLength{})
	_, err := onet.GlobalProtocolRegister(ShufflingPlusDDTProtocolName, NewShufflingPlusDDTProtocol)
	log.ErrFatal(err, "Failed to register the <ShufflingPlusDDT> protocol:")
}

// Messages
//______________________________________________________________________________________________________________________

// ShufflingPlusDDTMessage represents a message containing data to shuffle and tag
type ShufflingPlusDDTMessage struct {
	Data     []libunlynx.CipherVector
	ShuffKey kyber.Point // the key to use for shuffling
}

// ShufflingPlusDDTBytesMessage represents a ShufflingPlusDDTMessage in bytes
type ShufflingPlusDDTBytesMessage struct {
	Data     []byte
	ShuffKey []byte
}

// ShufflingPlusDDTBytesLength is a message containing the lengths to read a ShufflingPlusDDTMessage in bytes
type ShufflingPlusDDTBytesLength struct {
	CVLengths []byte
}

// Structs
//______________________________________________________________________________________________________________________

// shufflingPlusDDTBytesStruct contains a ShufflingPlusDDTMessage in bytes
type shufflingPlusDDTBytesStruct struct {
	*onet.TreeNode
	ShufflingPlusDDTBytesMessage
}

// shufflingBytesLengthStruct contains the length of the message
type shufflingPlusDDTBytesLengthStruct struct {
	*onet.TreeNode
	ShufflingPlusDDTBytesLength
}

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingPlusDDTProtocol hold the state of a shuffling+ddt protocol instance.
type ShufflingPlusDDTProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.DeterministCipherVector

	// Protocol communication channels
	LengthNodeChannel         chan shufflingPlusDDTBytesLengthStruct
	PreviousNodeInPathChannel chan shufflingPlusDDTBytesStruct

	// Protocol state data
	TargetData        *[]libunlynx.CipherVector
	SurveySecretKey   *kyber.Scalar
	Precomputed       []libunlynxshuffle.CipherVectorScalar
	nextNodeInCircuit *onet.TreeNode

	// Proofs
	Proofs bool
}

// NewShufflingPlusDDTProtocol constructs neff shuffle + ddt protocol instance.
func NewShufflingPlusDDTProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi := &ShufflingPlusDDTProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.DeterministCipherVector),
	}

	if err := pi.RegisterChannel(&pi.PreviousNodeInPathChannel); err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	if err := pi.RegisterChannel(&pi.LengthNodeChannel); err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	// choose next node in circuit
	nodeList := n.Tree().List()
	for i, node := range nodeList {
		if n.TreeNode().Equal(node) {
			pi.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}
	return pi, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ShufflingPlusDDTProtocol) Start() error {

	if p.TargetData == nil {
		return fmt.Errorf("no data is given")
	}
	nbrSqCVs := len(*p.TargetData)
	log.Lvl1("["+p.Name()+"]", " started a Shuffling+DDT Protocol (", nbrSqCVs, " responses)")

	shuffleTarget := *p.TargetData

	// STEP 4: Send to next node

	message := ShufflingPlusDDTBytesMessage{}
	var cvLengthsByte []byte
	var err error

	message.Data, cvLengthsByte, err = (&ShufflingPlusDDTMessage{Data: shuffleTarget}).ToBytes()
	if err != nil {
		return err
	}

	message.ShuffKey, err = libunlynx.AbstractPointsToBytes([]kyber.Point{p.Tree().Roster.Aggregate})
	if err != nil {
		return err
	}

	err = p.sendToNext(&ShufflingPlusDDTBytesLength{CVLengths: cvLengthsByte})
	if err != nil {
		return err
	}

	err = p.sendToNext(&message)
	if err != nil {
		return err
	}
	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingPlusDDTProtocol) Dispatch() error {
	defer p.Done()

	var shufflingPlusDDTBytesMessageLength shufflingPlusDDTBytesLengthStruct
	select {
	case shufflingPlusDDTBytesMessageLength = <-p.LengthNodeChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <shufflingPlusDDTBytesMessageLength> on time")
	}

	var spDDTbs shufflingPlusDDTBytesStruct
	select {
	case spDDTbs = <-p.PreviousNodeInPathChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <spDDTbs> on time")
	}

	readData := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(ReadData)")
	sm := ShufflingPlusDDTMessage{}
	err := sm.FromBytes(spDDTbs.Data, spDDTbs.ShuffKey, shufflingPlusDDTBytesMessageLength.CVLengths)
	if err != nil {
		return err
	}

	libunlynx.EndTimer(readData)

	// STEP 1: Shuffling of the data
	step1 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step1-Shuffling)")
	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}
	shuffledData, pi, beta := libunlynxshuffle.ShuffleSequence(sm.Data, libunlynx.SuiTe.Point().Base(), sm.ShuffKey, p.Precomputed)
	libunlynx.EndTimer(step1)

	if p.Proofs {
		if _, err := libunlynxshuffle.ShuffleProofCreation(sm.Data, shuffledData, libunlynx.SuiTe.Point().Base(), sm.ShuffKey, beta, pi); err != nil {
			return err
		}
	}

	// STEP 2: Addition of secret (first round of DDT, add value derivated from ephemeral secret to message)
	step2 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step2-DDTAddition)")
	toAdd := libunlynx.SuiTe.Point().Mul(*p.SurveySecretKey, libunlynx.SuiTe.Point().Base()) //siB (basically)

	mutex := sync.Mutex{}
	wg := sync.WaitGroup{}
	for i := 0; i < len(shuffledData); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(shuffledData); j++ {
				for k := range shuffledData[i+j] {
					r := libunlynx.SuiTe.Point().Add(shuffledData[i+j][k].C, toAdd)
					if p.Proofs {
						_, tmpErr := libunlynxdetertag.DeterministicTagAdditionProofCreation(shuffledData[i+j][k].C, *p.SurveySecretKey, toAdd, r)
						if tmpErr != nil {
							mutex.Lock()
							err = tmpErr
							mutex.Unlock()
							return
						}
					}
					shuffledData[i+j][k].C = r
				}
			}
		}(i)
	}
	wg.Wait()

	if err != nil {
		return err
	}
	libunlynx.EndTimer(step2)

	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	// STEP 3: Partial Decryption (second round of DDT, deterministic tag creation)
	step3 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step3-DDT)")
	mutex = sync.Mutex{}
	wg = sync.WaitGroup{}
	for i := 0; i < len(shuffledData); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(shuffledData); j++ {
				vBef := shuffledData[i+j]
				vAft := libunlynxdetertag.DeterministicTagSequence(vBef, p.Private(), *p.SurveySecretKey)
				if p.Proofs {
					_, tmpErr := libunlynxdetertag.DeterministicTagCrListProofCreation(vBef, vAft, p.Public(), *p.SurveySecretKey, p.Private())
					if tmpErr != nil {
						mutex.Lock()
						err = tmpErr
						mutex.Unlock()
						return
					}
				}
				copy(shuffledData[i+j], vAft)
			}
		}(i)
	}
	wg.Wait()
	libunlynx.EndTimer(step3)

	var taggedData []libunlynx.DeterministCipherVector

	if p.IsRoot() {
		prepareResult := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(PrepareResult)")
		taggedData = make([]libunlynx.DeterministCipherVector, len(*p.TargetData))
		size := 0
		for i, v := range shuffledData {
			taggedData[i] = make(libunlynx.DeterministCipherVector, len(v))
			for j, el := range v {
				taggedData[i][j] = libunlynx.DeterministCipherText{Point: el.C}
				size++
			}
		}
		libunlynx.EndTimer(prepareResult)
		log.Lvl1(p.ServerIdentity(), " completed shuffling+DDT protocol (", size, "responses )")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on shuffling+DDT protocol")
	}

	// STEP 4: Send to next node

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.FeedbackChannel <- taggedData
	} else {
		var err error

		sendData := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(SendData)")
		message := ShufflingPlusDDTBytesMessage{}
		var cvBytesLengths []byte
		message.Data, cvBytesLengths, err = (&ShufflingPlusDDTMessage{Data: shuffledData}).ToBytes()
		if err != nil {
			return err
		}

		// we have to subtract the key p.Public to the shuffling key (we partially decrypt during tagging)
		message.ShuffKey, err = libunlynx.AbstractPointsToBytes([]kyber.Point{sm.ShuffKey.Sub(sm.ShuffKey, p.Public())})
		libunlynx.EndTimer(sendData)
		if err != nil {
			return err
		}

		if err := p.sendToNext(&ShufflingPlusDDTBytesLength{cvBytesLengths}); err != nil {
			return err
		}
		if err := p.sendToNext(&message); err != nil {
			return err
		}
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List().
func (p *ShufflingPlusDDTProtocol) sendToNext(msg interface{}) error {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		return err
	}
	return nil
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts a ShufflingPlusDDTMessage to a byte array
func (spddtm *ShufflingPlusDDTMessage) ToBytes() ([]byte, []byte, error) {
	return libunlynx.ArrayCipherVectorToBytes(spddtm.Data)
}

// FromBytes converts a byte array to a ShufflingPlusDDTMessage. Note that you need to create the (empty) object beforehand.
func (spddtm *ShufflingPlusDDTMessage) FromBytes(data []byte, shuffKey []byte, cvLengthsByte []byte) error {
	var err error
	(*spddtm).Data, err = libunlynx.FromBytesToArrayCipherVector(data, cvLengthsByte)
	if err != nil {
		return err
	}

	dataP, err := libunlynx.FromBytesToAbstractPoints(shuffKey)
	if err != nil {
		return err
	}
	(*spddtm).ShuffKey = dataP[0]
	return nil
}
