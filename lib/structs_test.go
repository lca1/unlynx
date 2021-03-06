package libunlynx_test

import (
	"strconv"
	"testing"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/tools"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
)

// TestAddClientResponse tests the addition of two client response objects
func TestAddClientResponse(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	sum := []int64{0, 2, 4, 6, 8}

	secKey, pubKey := libunlynx.GenKey()

	cr1 := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}
	cr2 := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}

	newCr := libunlynx.FilteredResponse{}
	newCr.GroupByEnc = *libunlynx.EncryptIntVector(pubKey, grouping)
	newCr.AggregatingAttributes = *libunlynx.NewCipherVector(len(cr1.AggregatingAttributes))
	newCr.Add(cr1, cr2)

	assert.Equal(t, sum, libunlynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

func TestAddInMap(t *testing.T) {
	_, pubKey := libunlynx.GenKey()
	gkey := libunlynx.GroupingKey("test")

	cv := make(libunlynx.CipherVector, 5)
	for i := 0; i < 5; i++ {
		cv[i] = *libunlynx.EncryptInt(pubKey, int64(i))
	}
	fr := libunlynx.FilteredResponse{GroupByEnc: cv, AggregatingAttributes: cv}

	mapToTest := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	_, ok := mapToTest[gkey]
	assert.False(t, ok)

	libunlynx.AddInMap(mapToTest, gkey, fr)
	v, ok2 := mapToTest[gkey]
	assert.True(t, ok2)
	assert.Equal(t, v, fr)
}

// A function that converts and decrypts a map[string][]byte -> map[string]Ciphertext ->  map[string]int64
func decryptMapBytes(secKey kyber.Scalar, data map[string][]byte) (map[string]int64, error) {
	result := make(map[string]int64)

	for k, v := range data {
		ct := libunlynx.CipherText{}
		err := ct.FromBytes(v)
		if err != nil {
			return nil, err
		}
		result[k] = libunlynx.DecryptInt(secKey, ct)
	}
	return result, nil
}

// TestEncryptDpClearResponse tests the encryption of a DpClearResponse object
func TestEncryptDpClearResponse(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	groupingClear := libunlynxtools.ConvertDataToMap([]int64{2}, "g", 0)
	groupingEnc := libunlynxtools.ConvertDataToMap([]int64{1}, "g", len(groupingClear))
	whereClear := libunlynxtools.ConvertDataToMap([]int64{}, "w", 0)
	whereEnc := libunlynxtools.ConvertDataToMap([]int64{1, 1}, "w", len(whereClear))
	aggrClear := libunlynxtools.ConvertDataToMap([]int64{1}, "s", 0)
	aggrEnc := libunlynxtools.ConvertDataToMap([]int64{1, 5, 4, 0}, "s", len(aggrClear))

	ccr := libunlynx.DpClearResponse{
		GroupByClear:               groupingClear,
		GroupByEnc:                 groupingEnc,
		WhereClear:                 whereClear,
		WhereEnc:                   whereEnc,
		AggregatingAttributesClear: aggrClear,
		AggregatingAttributesEnc:   aggrEnc,
	}

	cr, err := libunlynx.EncryptDpClearResponse(ccr, pubKey, false)
	assert.NoError(t, err)

	assert.Equal(t, ccr.GroupByClear, groupingClear)
	mp, err := decryptMapBytes(secKey, cr.GroupByEnc)
	assert.NoError(t, err)
	assert.Equal(t, ccr.GroupByEnc, mp)
	assert.Equal(t, ccr.WhereClear, whereClear)
	mp, err = decryptMapBytes(secKey, cr.WhereEnc)
	assert.NoError(t, err)
	assert.Equal(t, ccr.WhereEnc, mp)
	assert.Equal(t, ccr.AggregatingAttributesClear, aggrClear)
	mp, err = decryptMapBytes(secKey, cr.AggregatingAttributesEnc)
	assert.NoError(t, err)
	assert.Equal(t, ccr.AggregatingAttributesEnc, mp)
}

// TestFilteredResponseConverter tests the FilteredResponse converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestFilteredResponseConverter(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := libunlynx.GenKey()

	cr := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}

	crb, acbLength, aabLength, err := cr.ToBytes()
	assert.NoError(t, err)

	newCr := libunlynx.FilteredResponse{}
	err = newCr.FromBytes(crb, aabLength, acbLength)
	assert.NoError(t, err)
	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestFilteredResponseDetConverter tests the FilteredResponseDet converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseDetConverter(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	crd := libunlynx.FilteredResponseDet{DetTagGroupBy: libunlynx.Key([]int64{1}), Fr: libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}}

	crb, acbLength, aabLength, dtbLength, err := crd.ToBytes()
	assert.NoError(t, err)

	newCrd := libunlynx.FilteredResponseDet{}
	err = newCrd.FromBytes(crb, acbLength, aabLength, dtbLength)
	assert.NoError(t, err)
	gkey, err := libunlynx.UnKey(newCrd.DetTagGroupBy)
	assert.NoError(t, err)
	assert.Equal(t, grouping, gkey)
	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newCrd.Fr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCrd.Fr.GroupByEnc))
}

// TestProcessResponseConverter tests the ProcessResponse converter (to bytes).
func TestProcessResponseConverter(t *testing.T) {
	whereEnc := []int64{1, 5, 6}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := libunlynx.GenKey()

	pr := libunlynx.ProcessResponse{
		WhereEnc:              *libunlynx.EncryptIntVector(pubKey, whereEnc),
		GroupByEnc:            *libunlynx.EncryptIntVector(pubKey, grouping),
		AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating),
	}

	b, gacbLength, aabLength, pgaebLength, err := pr.ToBytes()
	assert.NoError(t, err)
	newPr := libunlynx.ProcessResponse{}
	err = newPr.FromBytes(b, gacbLength, aabLength, pgaebLength)
	assert.NoError(t, err)
	assert.Equal(t, whereEnc, libunlynx.DecryptIntVector(secKey, &newPr.WhereEnc))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newPr.GroupByEnc))
	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newPr.AggregatingAttributes))
}

func TestProcessResponseDetConverter(t *testing.T) {
	whereEnc := []int64{1, 5, 6}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	_, pubKey := libunlynx.GenKey()

	pr := libunlynx.ProcessResponse{
		WhereEnc:              *libunlynx.EncryptIntVector(pubKey, whereEnc),
		GroupByEnc:            *libunlynx.EncryptIntVector(pubKey, grouping),
		AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating),
	}

	detTagWhere := make([]libunlynx.GroupingKey, 2)
	detTagWhere[0] = libunlynx.GroupingKey("test1")
	detTagWhere[1] = libunlynx.GroupingKey("test2")
	prDet := libunlynx.ProcessResponseDet{
		PR:            pr,
		DetTagGroupBy: "",
		DetTagWhere:   detTagWhere,
	}

	b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength, err := prDet.ToBytes()
	assert.NoError(t, err)
	newPrDet := libunlynx.ProcessResponseDet{
		PR:            libunlynx.ProcessResponse{},
		DetTagGroupBy: "",
		DetTagWhere:   nil,
	}
	err = newPrDet.FromBytes(b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength)
	assert.NoError(t, err)
	assert.Equal(t, prDet.DetTagGroupBy, newPrDet.DetTagGroupBy)
	assert.Equal(t, prDet.DetTagWhere, newPrDet.DetTagWhere)
}

func TestDPResponseConverter(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	k := 5
	dpResponseToSend := libunlynx.DpResponseToSend{
		WhereClear:                 make(map[string]int64),
		WhereEnc:                   make(map[string][]byte),
		GroupByClear:               make(map[string]int64),
		GroupByEnc:                 make(map[string][]byte),
		AggregatingAttributesClear: make(map[string]int64),
		AggregatingAttributesEnc:   make(map[string][]byte),
	}
	for i := 0; i < k; i++ {
		var err error

		dpResponseToSend.GroupByClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.WhereClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.AggregatingAttributesClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.GroupByEnc[strconv.Itoa(i)], err = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		assert.NoError(t, err)
		dpResponseToSend.WhereEnc[strconv.Itoa(i)], err = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		assert.NoError(t, err)
		dpResponseToSend.AggregatingAttributesEnc[strconv.Itoa(i)], err = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		assert.NoError(t, err)
	}

	dpResponse := libunlynx.DpResponse{
		WhereClear:                 nil,
		WhereEnc:                   nil,
		GroupByClear:               nil,
		GroupByEnc:                 nil,
		AggregatingAttributesClear: nil,
		AggregatingAttributesEnc:   nil,
	}

	err := dpResponse.FromDpResponseToSend(dpResponseToSend)
	assert.NoError(t, err)

	for i := 0; i < k; i++ {
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.GroupByEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.WhereEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.AggregatingAttributesEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, dpResponse.GroupByClear[strconv.Itoa(i)], int64(i))
		assert.Equal(t, dpResponse.WhereClear[strconv.Itoa(i)], int64(i))
		assert.Equal(t, dpResponse.AggregatingAttributesClear[strconv.Itoa(i)], int64(i))
	}
}

func TestMapBytesToMapCipherText(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	k := 5
	bMap := make(map[string][]byte)
	var err error
	for i := 0; i < k; i++ {
		bMap[strconv.Itoa(i)], err = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		assert.NoError(t, err)
	}
	ctMap, err := libunlynx.MapBytesToMapCipherText(bMap)
	assert.NoError(t, err)
	for i := 0; i < k; i++ {
		assert.Equal(t, libunlynx.DecryptInt(secKey, ctMap[strconv.Itoa(i)]), int64(i))
	}
}
