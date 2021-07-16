package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/protocols/utils"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"time"
)

func init() {
	onet.SimulationRegister("AddRmServer", NewAddRmSimulation)

}

// AddRmSimulation hogithub.com/ldsec/ the state of a simulation.
type AddRmSimulation struct {
	onet.SimulationBFTree

	NbrResponses int //to make sense all the different attributes are encrypted
	Proofs       bool
	Add          bool
}

// NewAddRmSimulation constructs an adding/removing protocol simulation.
func NewAddRmSimulation(config string) (onet.Simulation, error) {
	sim := &AddRmSimulation{}
	_, err := toml.Decode(config, sim)

	if err != nil {
		return nil, err
	}
	return sim, nil
}

// Setup initializes the simulation.
func (sim *AddRmSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

// Run starts the simulation.
func (sim *AddRmSimulation) Run(config *onet.SimulationConfig) error {
	for round := 0; round < sim.Rounds; round++ {

		rooti, err := config.Overlay.CreateProtocol("AddRmServer", config.Tree, onet.NilServiceID)

		if err != nil {
			return err
		}

		root := rooti.(*protocolsunlynxutils.AddRmServerProtocol)

		secKey := libunlynx.SuiTe.Scalar().Pick(random.New())
		newSecKey := libunlynx.SuiTe.Scalar().Pick(random.New())
		pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

		ct := make(libunlynx.CipherVector, sim.NbrResponses)
		for i := range ct {
			ct[i] = *libunlynx.EncryptInt(pubKey, 1)
		}

		root.ProtocolInstance().(*protocolsunlynxutils.AddRmServerProtocol).TargetOfTransformation = ct
		root.ProtocolInstance().(*protocolsunlynxutils.AddRmServerProtocol).Proofs = sim.Proofs
		root.ProtocolInstance().(*protocolsunlynxutils.AddRmServerProtocol).Add = sim.Add
		root.ProtocolInstance().(*protocolsunlynxutils.AddRmServerProtocol).KeyToRm = newSecKey

		round := libunlynx.StartTimer("_LocalAddRm(Simulation")

		if err := root.Start(); err != nil {
			return err
		}

		select {
		case results := <-root.ProtocolInstance().(*protocolsunlynxutils.AddRmServerProtocol).FeedbackChannel:
			log.Lvl1("Number of aggregated lines: ", len(results))
			libunlynx.EndTimer(round)
		case <-time.After(libunlynx.TIMEOUT):
			return fmt.Errorf("simulation didn't finish in time")
		}
	}

	return nil
}
