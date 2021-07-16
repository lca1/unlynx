package main

import (
	"fmt"
	"github.com/ldsec/unlynx/data"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/tools"
	"github.com/ldsec/unlynx/services"
	"strconv"

	"github.com/BurntSushi/toml"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
)

//Defines the simulation for the default service to be run with cothority/simul.
func init() {
	onet.SimulationRegister("ServiceUnLynxDefault", NewSimulationUnLynx)
}

// SimulationUnLynx the state of a simulation.
type SimulationUnLynx struct {
	onet.SimulationBFTree

	NbrDPs               int     //number of clients (or in other words data holders)
	NbrResponsesTot      int64   //number of survey entries (ClientClearResponse) per host
	NbrResponsesFiltered int64   //number of entries to be filtered (the ones we keep)
	NbrGroupsClear       int64   //number of non-sensitive (clear) grouping attributes
	NbrGroupsEnc         int64   //number of sensitive (encrypted) grouping attributes
	NbrGroupAttributes   []int64 //number of different groups inside each grouping attribute
	NbrWhereClear        int64   //number of non-sensitive (clear) where attributes
	NbrWhereEncrypted    int64   //number of sensitive (encrypted) where attributes
	NbrAggrClear         int64   //number of non-sensitive (clear) aggregating attributes
	NbrAggrEncrypted     int64   //number of sensitive (encrypted) aggregating attributes
	Count                bool    //toggle count queries
	RandomGroups         bool    //generate data randomly or num entries == num groups (deterministically)
	DataRepetitions      int     //repeat the number of entries x times (e.g. 1 no repetition; 1000 repetitions)
	Proofs               bool    //with proofs of correctness everywhere
}

// NewSimulationUnLynx constructs a full UnLynx service simulation.
func NewSimulationUnLynx(config string) (onet.Simulation, error) {
	es := &SimulationUnLynx{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (sim *SimulationUnLynx) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
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
func (sim *SimulationUnLynx) Run(config *onet.SimulationConfig) error {
	var start *monitor.TimeMeasure
	// Setup Simulation
	nbrHosts := config.Tree.Size()
	log.Lvl1("Size:", nbrHosts, ", Rounds:", sim.Rounds)

	// Does not make sense to have more servers than clients!!
	if nbrHosts > sim.NbrDPs {
		return fmt.Errorf("hosts: " + strconv.FormatInt(int64(nbrHosts), 10) + " must be the same or lower as num_clients " + strconv.FormatInt(int64(sim.NbrDPs), 10))
	}
	el := (*config.Tree).Roster

	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Starting round", round, el)
		client := servicesunlynx.NewUnLynxClient(el.List[0], strconv.Itoa(0))

		// Define how many data providers for each server
		nbrDPs := make(map[string]int64)
		for _, server := range el.List {
			nbrDPs[server.String()] = 1 // 1 DP(s) for each server
		}

		// Generate Survey Data

		// Aggregating attributes
		NbrAggr := sim.NbrAggrClear + sim.NbrAggrEncrypted
		sum := make([]string, NbrAggr)
		for i := 0; i < int(NbrAggr); i++ {
			sum[i] = "s" + strconv.Itoa(i)
		}
		count := sim.Count

		// Where attributes + predicate
		NbrWhere := sim.NbrWhereClear + sim.NbrWhereEncrypted
		whereQueryValues := make([]libunlynx.WhereQueryAttribute, NbrWhere)

		predicate := ""
		counter := 0

		if int(NbrWhere) > 0 {
			for i := 0; i < int(NbrWhere); i++ {
				whereQueryValues[i] = libunlynx.WhereQueryAttribute{Name: "w" + strconv.Itoa(i), Value: *libunlynx.EncryptInt(el.Aggregate, 1)}
				predicate = predicate + " v" + strconv.Itoa(counter) + " == v" + strconv.Itoa(counter+1) + " &&"
				counter = counter + 2
			}
			// remove the last &&
			predicate = predicate[:len(predicate)-2]
		}

		// Group by attributes
		NbrGroups := sim.NbrGroupsClear + sim.NbrGroupsEnc
		groupBy := make([]string, NbrGroups)
		for i := 0; i < int(NbrGroups); i++ {
			groupBy[i] = "g" + strconv.Itoa(i)
		}

		surveyID, err := client.SendSurveyCreationQuery(el, servicesunlynx.SurveyID(""), nil, nbrDPs, sim.Proofs, false, sum, count, whereQueryValues, predicate, groupBy)
		if err != nil {
			return err
		}

		// RandomGroups (true/false) is to respectively generate random or non random entries
		testData, err := dataunlynx.GenerateData(int64(sim.NbrDPs), sim.NbrResponsesTot, sim.NbrResponsesFiltered, sim.NbrGroupsClear, sim.NbrGroupsEnc,
			sim.NbrWhereClear, sim.NbrWhereEncrypted, sim.NbrAggrClear, sim.NbrAggrEncrypted, sim.NbrGroupAttributes, sim.RandomGroups)
		if err != nil {
			return err
		}

		/// START SERVICE PROTOCOL
		if libunlynx.TIME {
			start = monitor.NewTimeMeasure("SendingData")
		}

		log.Lvl1("Sending response data... ")
		dataHolder := make([]*servicesunlynx.API, sim.NbrDPs)
		wg := libunlynx.StartParallelize(uint(len(dataHolder)))

		for i, client := range dataHolder {
			start := libunlynx.StartTimer(strconv.Itoa(i) + "_IndividualSendingData")
			go func(i int, client *servicesunlynx.API) {

				dataCollection := testData[strconv.Itoa(i)]
				server := el.List[i%nbrHosts]

				client = servicesunlynx.NewUnLynxClient(server, strconv.Itoa(i+1))
				err := client.SendSurveyResponseQuery(*surveyID, dataCollection, el.Aggregate, sim.DataRepetitions, count)
				wg.Done(err)
			}(i, client)
			libunlynx.EndTimer(start)

		}
		libunlynx.EndParallelize(wg)
		libunlynx.EndTimer(start)

		if err != nil {
			return err
		}

		start := libunlynx.StartTimer("Simulation")

		grp, aggr, err := client.SendSurveyResultsQuery(*surveyID)
		if err != nil {
			return fmt.Errorf("service could not output the results: %v", err)
		}

		libunlynx.EndTimer(start)
		// END SERVICE PROTOCOL

		// Print Output
		allData := make([]libunlynx.DpClearResponse, 0)
		log.Lvl1("Service output:")
		for i := range *grp {
			log.Lvl1(i, ")", (*grp)[i], "->", (*aggr)[i])
			allData = append(allData, libunlynx.DpClearResponse{GroupByClear: libunlynxtools.ConvertDataToMap((*grp)[i], "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap((*aggr)[i], "s", 0)})
		}

		// Test Service Simulation
		if dataunlynx.CompareClearResponses(dataunlynx.ComputeExpectedResult(testData, sim.DataRepetitions, true), allData) {
			log.Lvl1("Result is right! :)")
		} else {
			log.Lvl1("Result is wrong! :(")
		}
	}

	return nil
}
