package main

import (
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"

	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	onet.SimulationRegister("Shuffling", NewShufflingSimulation)
}

// ShufflingSimulation is the structure holding the state of the simulation.
type ShufflingSimulation struct {
	onet.SimulationBFTree

	NbrGroupAttributes int
	NbrAggrAttributes  int
	NbrResponses       int
	Proofs             bool
	PreCompute         bool
}

// NewShufflingSimulation is a constructor for the simulation.
func NewShufflingSimulation(config string) (onet.Simulation, error) {
	sim := &ShufflingSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes a simulation.
func (sim *ShufflingSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}
	log.Lvl1("Setup done")
	return sc, nil
}

// Node registers a ShufflingSimul (with access to the ShufflingSimulation object) for every node
func (sim *ShufflingSimulation) Node(config *onet.SimulationConfig) error {
	config.Server.ProtocolRegister("ShufflingSimul",
		func(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewShufflingSimul(tni, sim)
		})

	return sim.SimulationBFTree.Node(config)
}

// Run starts the simulation.
func (sim *ShufflingSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round)
		rooti, err := config.Overlay.CreateProtocol("ShufflingSimul", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsUnLynx.ShufflingProtocol)

		//complete protocol time measurement
		round := libUnLynx.StartTimer("_Shuffling(SIMULATION)")

		root.Start()

		<-root.ProtocolInstance().(*protocolsUnLynx.ShufflingProtocol).FeedbackChannel
		libUnLynx.EndTimer(round)
	}

	return nil
}

// NewShufflingSimul is a custom protocol constructor specific for simulation purposes.
func NewShufflingSimul(tni *onet.TreeNodeInstance, sim *ShufflingSimulation) (onet.ProtocolInstance, error) {
	protocol, err := protocolsUnLynx.NewShufflingProtocol(tni)
	pap := protocol.(*protocolsUnLynx.ShufflingProtocol)
	pap.Proofs = sim.Proofs
	if sim.PreCompute {
		pap.Precomputed = libUnLynx.CreatePrecomputedRandomize(network.Suite.Point().Base(), tni.Roster().Aggregate, network.Suite.Cipher(tni.Private().Bytes()), int(sim.NbrGroupAttributes)+int(sim.NbrAggrAttributes), 10)
	}
	if tni.IsRoot() {
		aggregateKey := pap.Roster().Aggregate

		// Creates dummy data...
		clientResponses := make([]libUnLynx.ProcessResponse, sim.NbrResponses)
		tabGroup := make([]int64, sim.NbrGroupAttributes)
		tabAttr := make([]int64, sim.NbrAggrAttributes)

		for i := 0; i < sim.NbrGroupAttributes; i++ {
			tabGroup[i] = int64(1)
		}
		for i := 0; i < sim.NbrAggrAttributes; i++ {
			tabAttr[i] = int64(1)
		}

		encryptedGrp := *libUnLynx.EncryptIntVector(aggregateKey, tabGroup)
		encryptedAttr := *libUnLynx.EncryptIntVector(aggregateKey, tabAttr)
		clientResponse := libUnLynx.ProcessResponse{GroupByEnc: encryptedGrp, AggregatingAttributes: encryptedAttr}

		for i := 0; i < sim.NbrResponses; i++ {
			clientResponses[i] = clientResponse
		}

		pap.TargetOfShuffle = &clientResponses
	}

	return pap, err
}
