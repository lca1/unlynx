package libunlynx_test

import (
	"fmt"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const file = "pre_compute_multiplications.gob"
const k = 5

func TestWriteToGobFile(t *testing.T) {
	dataCipher := make([]libunlynx.CipherVectorScalar, 0)

	cipher := libunlynx.CipherVectorScalar{}

	v1 := libunlynx.SuiTe.Scalar().Pick(random.New())
	v2 := libunlynx.SuiTe.Scalar().Pick(random.New())

	cipher.S = append(cipher.S, v1, v2)

	vK := libunlynx.SuiTe.Point()
	vC := libunlynx.SuiTe.Point()

	ct := libunlynx.CipherText{K: vK, C: vC}

	cipher.CipherV = append(cipher.CipherV, ct)
	dataCipher = append(dataCipher, cipher)

	// we need bytes (or any other serializable data) to be able to store in a gob file
	encoded, err := libunlynx.EncodeCipherVectorScalar(dataCipher)

	if err != nil {
		log.Fatal("Error during marshling")
	}

	libunlynx.WriteToGobFile(file, encoded)

	fmt.Println(dataCipher)
}

func TestReadFromGobFile(t *testing.T) {
	var encoded []libunlynx.CipherVectorScalarBytes

	libunlynx.ReadFromGobFile(file, &encoded)

	dataCipher, err := libunlynx.DecodeCipherVectorScalar(encoded)

	if err != nil {
		log.Fatal("Error during unmarshling")
	}

	fmt.Println(dataCipher)
	os.Remove("pre_compute_multiplications.gob")
}

func TestAddInMap(t *testing.T) {
	_, pubKey := libunlynx.GenKey()
	key := libunlynx.GroupingKey("test")

	cv := make(libunlynx.CipherVector, k)
	for i := 0; i < k; i++ {
		cv[i] = *libunlynx.EncryptInt(pubKey, int64(i))
	}
	fr := libunlynx.FilteredResponse{GroupByEnc: cv, AggregatingAttributes: cv}

	mapToTest := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	_, ok := mapToTest[key]
	assert.False(t, ok)

	libunlynx.AddInMap(mapToTest, key, fr)
	v, ok2 := mapToTest[key]
	assert.True(t, ok2)
	assert.Equal(t, v, fr)
}

func TestInt64ArrayToString(t *testing.T) {
	toTest := make([]int64, k)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	str := libunlynx.Int64ArrayToString(toTest)
	retVal := libunlynx.StringToInt64Array(str)

	assert.Equal(t, toTest, retVal)
}

func TestConvertDataToMap(t *testing.T) {
	toTest := make([]int64, k)
	for i := range toTest {
		toTest[i] = int64(i)
	}

	first := "test"
	start := 1
	mapRes := libunlynx.ConvertDataToMap(toTest, first, start)
	arrayRes := libunlynx.ConvertMapToData(mapRes, first, start)

	assert.Equal(t, toTest, arrayRes)
}
