package protocolsunlynxutils_test

import (
	"testing"
	"time"

	"github.com/ldsec/unlynx/data"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/store"
	"github.com/ldsec/unlynx/lib/tools"
	"github.com/ldsec/unlynx/protocols/utils"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

func TestLocalClearAggregation(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("LocalClearAggregation", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynxutils.LocalClearAggregationProtocol)

	testData := generateClearData()
	aggregatedData := libunlynxstore.AddInClear(testData)

	protocol.TargetOfAggregation = testData
	feedback := protocol.FeedbackChannel

	assert.NoError(t, protocol.Start())

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, dataunlynx.CompareClearResponses(results, aggregatedData), true)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func generateClearData() []libunlynx.DpClearResponse {
	testData := make([]libunlynx.DpClearResponse, 6)

	testData[0] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{1, 2, 3, 4, 5}, "s", 0)}
	testData[1] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{0, 1, 4, 3, 0}, "s", 0)}
	testData[2] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{0, 1, 0, 1, 0}, "s", 0)}

	testData[3] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 1}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 1}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{0, 0, 0, 0, 0}, "w", 0)}
	testData[4] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 2}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 2}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{1, 3, 5, 7, 1}, "w", 0)}
	testData[5] = libunlynx.DpClearResponse{WhereClear: libunlynxtools.ConvertDataToMap([]int64{1, 3}, "w", 0), GroupByClear: libunlynxtools.ConvertDataToMap([]int64{1, 3}, "g", 0), AggregatingAttributesClear: libunlynxtools.ConvertDataToMap([]int64{1, 0, 1, 0, 1}, "w", 0)}

	return testData
}
