package libunlynx

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/fanliao/go-concurrentMap"
	"github.com/ldsec/unlynx/lib/tools"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3/log"
)

// MaxHomomorphicInt is upper bound for integers used in messages, a failed decryption will return this value.
const MaxHomomorphicInt int64 = 100000

// PointToInt creates a map between EC points and integers.
var PointToInt = concurrent.NewConcurrentMap()
var currentGreatestM kyber.Point
var currentGreatestInt int64
var mutex = sync.Mutex{}

// PublishedSimpleAdditionProof contains the two added ciphervectors and the resulting ciphervector
type PublishedSimpleAdditionProof struct {
	C1       CipherVector
	C2       CipherVector
	C1PlusC2 CipherVector
}

// CipherText is an ElGamal encrypted point.
type CipherText struct {
	K, C kyber.Point
}

// CipherVector is a slice of ElGamal encrypted points.
type CipherVector []CipherText

// DeterministCipherText deterministic encryption of a point.
type DeterministCipherText struct {
	Point kyber.Point
}

// DeterministCipherVector slice of deterministic encrypted points.
type DeterministCipherVector []DeterministCipherText

// Constructors
//______________________________________________________________________________________________________________________

// NewCipherText creates a ciphertext of null elements.
func NewCipherText() *CipherText {
	return &CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
}

// NewCipherTextFromBase64 creates a ciphertext of null elements.
func NewCipherTextFromBase64(b64Encoded string) (*CipherText, error) {
	cipherText := &CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
	if err := (*cipherText).Deserialize(b64Encoded); err != nil {
		return nil, err
	}
	return cipherText, nil
}

// NewCipherVector creates a ciphervector of null elements.
func NewCipherVector(length int) *CipherVector {
	cv := make(CipherVector, length)
	for i := 0; i < length; i++ {
		cv[i] = CipherText{SuiTe.Point().Null(), SuiTe.Point().Null()}
	}
	return &cv
}

// NewDeterministicCipherText create determinist cipher text of null element.
func NewDeterministicCipherText() *DeterministCipherText {
	dc := DeterministCipherText{SuiTe.Point().Null()}
	return &dc
}

// NewDeterministicCipherVector creates a vector of determinist ciphertext of null elements.
func NewDeterministicCipherVector(length int) *DeterministCipherVector {
	dcv := make(DeterministCipherVector, length)
	for i := 0; i < length; i++ {
		dcv[i] = DeterministCipherText{SuiTe.Point().Null()}
	}
	return &dcv
}

// Key Pairs
//----------------------------------------------------------------------------------------------------------------------

// GenKey generate an ElGamal public/private key pair.
func GenKey() (kyber.Scalar, kyber.Point) {
	keys := key.NewKeyPair(SuiTe)
	return keys.Private, keys.Public
}

// GenKeys generates ElGamal public/private key pairs.
func GenKeys(n int) (kyber.Point, []kyber.Scalar, []kyber.Point) {
	priv := make([]kyber.Scalar, n)
	pub := make([]kyber.Point, n)

	group := SuiTe.Point().Null()
	for i := 0; i < n; i++ {
		priv[i], pub[i] = GenKey()
		group.Add(group, pub[i])
	}
	return group, priv, pub
}

// SplitScalar splits a given scalar into multiple n+1 scalars
// The sum of the returned slice of scalars equals the given `rootScalar`
func SplitScalar(rootScalar kyber.Scalar, nbrSplits int) []kyber.Scalar {
	allScalars := make([]kyber.Scalar, nbrSplits)
	for i := range allScalars {
		allScalars[i] = RandomScalarSlice(1)[0]
		rootScalar = rootScalar.Sub(rootScalar, allScalars[i])
	}
	allScalars = append(allScalars, rootScalar)

	return allScalars
}

// Encryption
//______________________________________________________________________________________________________________________

// encryptPoint creates an elliptic curve point from a non-encrypted point and encrypt it using ElGamal encryption.
func encryptPoint(pubkey kyber.Point, M kyber.Point) (*CipherText, kyber.Scalar) {
	B := SuiTe.Point().Base()
	r := SuiTe.Scalar().Pick(random.New()) // ephemeral private key
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := SuiTe.Point().Mul(r, B)      // ephemeral DH public key
	S := SuiTe.Point().Mul(r, pubkey) // ephemeral DH shared secret
	C := SuiTe.Point().Add(S, M)      // message blinded with secret
	return &CipherText{K, C}, r
}

// IntToPoint maps an integer to a point in the elliptic curve
func IntToPoint(integer int64) kyber.Point {
	B := SuiTe.Point().Base()
	i := SuiTe.Scalar().SetInt64(integer)
	M := SuiTe.Point().Mul(i, B)
	return M
}

// PointToCipherText converts a point into a ciphertext
func PointToCipherText(point kyber.Point) CipherText {
	return CipherText{K: SuiTe.Point().Null(), C: point}
}

// IntToCipherText converts an int into a ciphertext
func IntToCipherText(integer int64) CipherText {
	return PointToCipherText(IntToPoint(integer))
}

// IntArrayToCipherVector converts an array of int to a CipherVector
func IntArrayToCipherVector(integers []int64) CipherVector {
	result := make(CipherVector, len(integers))
	for i, v := range integers {
		result[i] = PointToCipherText(IntToPoint(v))
	}
	return result
}

// EncryptInt encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptInt(pubkey kyber.Point, integer int64) *CipherText {
	encryption, _ := encryptPoint(pubkey, IntToPoint(integer))
	return encryption
}

// EncryptIntGetR encodes i as iB, encrypt it into a CipherText and returns a pointer to it. It also returns the randomness used in the encryption
func EncryptIntGetR(pubkey kyber.Point, integer int64) (*CipherText, kyber.Scalar) {
	encryption, r := encryptPoint(pubkey, IntToPoint(integer))
	return encryption, r
}

// EncryptScalar encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptScalar(pubkey kyber.Point, scalar kyber.Scalar) *CipherText {
	encryption, _ := encryptPoint(pubkey, SuiTe.Point().Mul(scalar, SuiTe.Point().Base()))
	return encryption
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer to it.
func EncryptIntVector(pubkey kyber.Point, intArray []int64) *CipherVector {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))

	for i := 0; i < len(intArray); i = i + VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
				cv[j+i] = *EncryptInt(pubkey, intArray[j+i])
			}
		}(i)

	}
	wg.Wait()

	return &cv
}

// EncryptIntVectorGetRs encrypts a []int into a CipherVector and returns a pointer to it. It also returns the randomness used in the encryption
func EncryptIntVectorGetRs(pubkey kyber.Point, intArray []int64) (*CipherVector, []kyber.Scalar) {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))
	rs := make([]kyber.Scalar, len(intArray))

	for i := 0; i < len(intArray); i = i + VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
				tmpCv, tmpR := EncryptIntGetR(pubkey, intArray[j+i])
				cv[j+i] = *tmpCv
				rs[j+i] = tmpR
			}
		}(i)

	}
	wg.Wait()

	return &cv, rs
}

// EncryptScalarVector encrypts a []scalar into a CipherVector and returns a pointer to it.
func EncryptScalarVector(pubkey kyber.Point, intArray []kyber.Scalar) *CipherVector {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))

	for i := 0; i < len(intArray); i = i + VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
				cv[j+i] = *EncryptScalar(pubkey, intArray[j+i])
			}
		}(i)

	}
	wg.Wait()

	return &cv
}

// NullCipherVector encrypts an 0-filled slice under the given public key.
func NullCipherVector(length int, pubkey kyber.Point) *CipherVector {
	return EncryptIntVector(pubkey, make([]int64, length))
}

// Decryption
//______________________________________________________________________________________________________________________

// decryptPoint decrypts an elliptic point from an El-Gamal cipher text.
func decryptPoint(prikey kyber.Scalar, c CipherText) kyber.Point {
	S := SuiTe.Point().Mul(prikey, c.K) // regenerate shared secret
	M := SuiTe.Point().Sub(c.C, S)      // use to un-blind the message
	return M
}

// DecryptInt decrypts an integer from an ElGamal cipher text where integer are encoded in the exponent.
func DecryptInt(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	v, err := discreteLog(M, false)
	if err != nil {
		return 0
	}
	return v
}

// DecryptIntWithNeg decrypts an integer from an ElGamal cipher text where integer are encoded in the exponent.
func DecryptIntWithNeg(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	v, err := discreteLog(M, true)
	if err != nil {
		return 0
	}
	return v
}

// DecryptIntVector decrypts a cipherVector.
func DecryptIntVector(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptInt(prikey, c)
	}
	return result
}

// DecryptIntVectorWithNeg decrypts a cipherVector.
func DecryptIntVectorWithNeg(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptIntWithNeg(prikey, c)
	}
	return result
}

// DecryptCheckZero check if the encrypted value is a 0. Does not do the complete decryption
func DecryptCheckZero(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	result := int64(1)
	if M.Equal(SuiTe.Point().Null()) {
		result = int64(0)
	}
	return result
}

// DecryptCheckZeroVector checks if encrypted values are 0 or not without doing the complete decryption.
func DecryptCheckZeroVector(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptCheckZero(prikey, c)
	}
	return result
}

// Brute-Forces the discrete log for integer decoding.
func discreteLog(P kyber.Point, checkNeg bool) (int64, error) {
	B := SuiTe.Point().Base()

	//check if the point is already in the table
	mutex.Lock()
	decrypted, ok := PointToInt.Get(P.String())
	if ok == nil && decrypted != nil {
		mutex.Unlock()
		return decrypted.(int64), nil
	}

	//otherwise, we complete/create the table while decrypting
	//initialise
	if currentGreatestInt == 0 {
		currentGreatestM = SuiTe.Point().Null()
	}
	foundPos := false
	foundNeg := false
	guess := currentGreatestM
	guessInt := currentGreatestInt
	guessNeg := SuiTe.Point().Null()
	guessIntMinus := int64(0)

	start := true
	for i := guessInt; i < MaxHomomorphicInt && !foundPos && !foundNeg; i = i + 1 {
		// check for 0 first
		if !start {
			guess = SuiTe.Point().Add(guess, B)
		}
		start = false

		guessInt = i
		if _, err := PointToInt.Put(guess.String(), guessInt); err != nil {
			return -1, err
		}
		if checkNeg {
			guessIntMinus = -guessInt
			guessNeg = SuiTe.Point().Mul(SuiTe.Scalar().SetInt64(guessIntMinus), B)
			if _, err := PointToInt.Put(guessNeg.String(), guessIntMinus); err != nil {
				return -1, err
			}

			if guessNeg.Equal(P) {
				foundNeg = true
			}
		}
		if !foundNeg && guess.Equal(P) {
			foundPos = true
		}
	}
	currentGreatestM = guess
	currentGreatestInt = guessInt
	mutex.Unlock()

	if !foundPos && !foundNeg {
		log.Error("out of bound encryption, bound is ", MaxHomomorphicInt)
		return 0, nil
	}

	if foundNeg {
		return guessIntMinus, nil
	}
	return guessInt, nil
}

// CreateDecryptionTable generated the lookup table for decryption of all the integers in [-limit, limit]
func CreateDecryptionTable(limit int64, pubKey kyber.Point, secKey kyber.Scalar) {
	dummy := EncryptInt(pubKey, int64(limit))
	DecryptIntWithNeg(secKey, *dummy)
}

// Homomorphic Operations
//______________________________________________________________________________________________________________________

// Add two ciphertexts and stores result in receiver.
func (c *CipherText) Add(c1, c2 CipherText) {
	c.C = SuiTe.Point().Add(c1.C, c2.C)
	c.K = SuiTe.Point().Add(c1.K, c2.K)
}

// MulCipherTextbyScalar multiplies two components of a ciphertext by a scalar
func (c *CipherText) MulCipherTextbyScalar(cMul CipherText, a kyber.Scalar) {
	c.C = SuiTe.Point().Mul(a, cMul.C)
	c.K = SuiTe.Point().Mul(a, cMul.K)
}

// Sub two ciphertexts and stores result in receiver.
func (c *CipherText) Sub(c1, c2 CipherText) {
	c.C = SuiTe.Point().Sub(c1.C, c2.C)
	c.K = SuiTe.Point().Sub(c1.K, c2.K)
}

// Equal checks equality between ciphertexts.
func (c *CipherText) Equal(c2 *CipherText) bool {
	return c2.K.Equal(c.K) && c2.C.Equal(c.C)
}

// Add two ciphervectors and stores result in receiver.
func (cv *CipherVector) Add(cv1, cv2 CipherVector) {
	var wg sync.WaitGroup

	for i := 0; i < len(cv1); i = i + VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < VPARALLELIZE && (j+i < len(cv1)); j++ {
				(*cv)[i+j].Add(cv1[i+j], cv2[i+j])
			}
		}(i)

	}
	wg.Wait()
}

// Sub two cipherVectors and stores result in receiver.
func (cv *CipherVector) Sub(cv1, cv2 CipherVector) {
	for i := range cv1 {
		(*cv)[i].Sub(cv1[i], cv2[i])
	}
}

// Equal checks equality between ciphervector.
func (cv *CipherVector) Equal(cv2 *CipherVector) bool {
	if cv == nil || cv2 == nil {
		return cv == cv2
	}

	if len(*cv) != len(*cv2) {
		return false
	}

	for i := range *cv2 {
		if !(*cv)[i].Equal(&(*cv2)[i]) {
			return false
		}
	}
	return true
}

// Acum adds all elements in a ciphervector
func (cv *CipherVector) Acum() CipherText {
	acum := (*cv)[0]
	for i := 1; i < len(*cv); i++ {
		acum.Add(acum, (*cv)[i])
	}
	return acum
}

// Representation
//______________________________________________________________________________________________________________________

// Key is used in order to get a map-friendly representation of grouping attributes to be used as keys.
func (dcv *DeterministCipherVector) Key() GroupingKey {
	var keyV []string
	for _, a := range *dcv {
		keyV = append(keyV, a.String())
	}
	return GroupingKey(strings.Join(keyV, ""))
}

// Equal checks equality between deterministic ciphervector.
func (dcv *DeterministCipherVector) Equal(dcv2 *DeterministCipherVector) bool {
	if dcv == nil || dcv2 == nil {
		return dcv == dcv2
	}

	if len(*dcv) != len(*dcv2) {
		return false
	}

	for i := range *dcv2 {
		if !(*dcv)[i].Equal(&(*dcv2)[i]) {
			return false
		}
	}
	return true
}

// Equal checks equality between deterministic ciphertexts.
func (dc *DeterministCipherText) Equal(dc2 *DeterministCipherText) bool {
	return dc2.Point.Equal(dc.Point)
}

// String representation of deterministic ciphertext.
func (dc *DeterministCipherText) String() string {
	cstr := "<nil>"
	if (*dc).Point != nil {
		cstr = (*dc).Point.String()
	}
	return fmt.Sprintf("%s", cstr)
}

// String returns a string representation of a ciphertext.
func (c *CipherText) String() string {
	cstr := "nil"
	kstr := cstr
	if (*c).C != nil {
		cstr = (*c).C.String()[1:7]
	}
	if (*c).K != nil {
		kstr = (*c).K.String()[1:7]
	}
	return fmt.Sprintf("CipherText{%s,%s}", kstr, cstr)
}

// RandomScalarSlice creates a random slice of chosen size
func RandomScalarSlice(k int) []kyber.Scalar {
	beta := make([]kyber.Scalar, k)
	rand := SuiTe.RandomStream()
	for i := 0; i < k; i++ {
		beta[i] = SuiTe.Scalar().Pick(rand)
		//beta[i] = SuiTe.Scalar().Zero() to test without shuffle
	}
	return beta
}

// RandomPermutation shuffles a slice of int
func RandomPermutation(k int) []int {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	// Pick a random permutation
	pi := make([]int, k)
	rand := SuiTe.RandomStream()
	for i := 0; i < k; i++ {
		// Initialize a trivial permutation
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- {
		randInt := random.Int(big.NewInt(int64(maxInt)), rand)
		// Shuffle by random swaps
		j := int(randInt.Int64()) % (i + 1)
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}
	return pi
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts a CipherVector to a byte array
func (cv *CipherVector) ToBytes() ([]byte, int, error) {
	b := make([]byte, 0)

	for _, el := range *cv {
		data, err := el.ToBytes()
		if err != nil {
			return nil, 0, err
		}
		b = append(b, data...)
	}

	return b, len(*cv), nil
}

// FromBytes converts a byte array to a CipherVector. Note that you need to create the (empty) object beforehand.
func (cv *CipherVector) FromBytes(data []byte, length int) error {
	*cv = make(CipherVector, length)
	cipherLength := 2 * SuiTe.PointLen()
	for i, pos := 0, 0; i < length*cipherLength; i, pos = i+cipherLength, pos+1 {
		ct := CipherText{}
		if err := ct.FromBytes(data[i : i+cipherLength]); err != nil {
			return err
		}
		(*cv)[pos] = ct
	}
	return nil
}

// ToBytes converts a CipherText to a byte array
func (c *CipherText) ToBytes() ([]byte, error) {
	k, errK := (*c).K.MarshalBinary()
	if errK != nil {
		return nil, errK
	}
	cP, errC := (*c).C.MarshalBinary()
	if errC != nil {
		return nil, errC
	}
	b := append(k, cP...)

	return b, nil
}

// FromBytes converts a byte array to a CipherText. Note that you need to create the (empty) object beforehand.
func (c *CipherText) FromBytes(data []byte) error {
	(*c).K = SuiTe.Point()
	(*c).C = SuiTe.Point()
	pointLength := SuiTe.PointLen()
	if err := (*c).K.UnmarshalBinary(data[:pointLength]); err != nil {
		return err
	}
	if err := (*c).C.UnmarshalBinary(data[pointLength:]); err != nil {
		return err
	}
	return nil
}

// Serialize encodes a CipherText in a base64 string
func (c *CipherText) Serialize() (string, error) {
	data, err := (*c).ToBytes()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

// Deserialize decodes a CipherText from a base64 string
func (c *CipherText) Deserialize(b64Encoded string) error {
	decoded, err := base64.URLEncoding.DecodeString(b64Encoded)
	if err != nil {
		return fmt.Errorf("invalid ciphertext (decoding failed): %v", err)
	}
	err = (*c).FromBytes(decoded)
	if err != nil {
		return err
	}
	return nil
}

// SerializeElement serializes a BinaryMarshaller-compatible element using base64 encoding (e.g. kyber.Point or kyber.Scalar)
func SerializeElement(el encoding.BinaryMarshaler) (string, error) {
	bytes, err := el.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("error marshalling element: %v", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// SerializePoint serializes a point
func SerializePoint(point kyber.Point) (string, error) {
	return SerializeElement(point)
}

// SerializeScalar serializes a scalar
func SerializeScalar(scalar encoding.BinaryMarshaler) (string, error) {
	return SerializeElement(scalar)
}

// DeserializePoint deserializes a point using base64 encoding
func DeserializePoint(encodedPoint string) (kyber.Point, error) {
	decoded, err := base64.URLEncoding.DecodeString(encodedPoint)
	if err != nil {
		return nil, fmt.Errorf("error decoding point: %v", err)
	}

	point := SuiTe.Point()
	err = point.UnmarshalBinary(decoded)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling point: %v", err)
	}

	return point, nil
}

// DeserializeScalar deserializes a scalar using base64 encoding
func DeserializeScalar(encodedScalar string) (kyber.Scalar, error) {
	decoded, err := base64.URLEncoding.DecodeString(encodedScalar)
	if err != nil {
		return nil, fmt.Errorf("error decoding scalar: %v", err)
	}

	scalar := SuiTe.Scalar()
	err = scalar.UnmarshalBinary(decoded)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling scalar: %v", err)
	}

	return scalar, nil
}

// AbstractPointsToBytes converts an array of kyber.Point to a byte array
func AbstractPointsToBytes(aps []kyber.Point) ([]byte, error) {
	var err error
	var apsBytes []byte
	response := make([]byte, 0)

	for i := range aps {
		apsBytes, err = aps[i].MarshalBinary()
		if err != nil {
			return nil, err
		}

		response = append(response, apsBytes...)
	}
	return response, nil
}

// FromBytesToAbstractPoints converts a byte array to an array of kyber.Point
func FromBytesToAbstractPoints(target []byte) ([]kyber.Point, error) {
	var err error
	aps := make([]kyber.Point, 0)
	pointLength := SuiTe.PointLen()
	for i := 0; i < len(target); i += pointLength {
		ap := SuiTe.Point()
		if err = ap.UnmarshalBinary(target[i : i+pointLength]); err != nil {
			return nil, err
		}

		aps = append(aps, ap)
	}
	return aps, nil
}

// ArrayCipherVectorToBytes converts an array of CipherVector to an array of bytes (plus an array of byte lengths)
func ArrayCipherVectorToBytes(data []CipherVector) ([]byte, []byte, error) {
	length := uint(len(data))

	b := make([]byte, 0)
	bb := make([][]byte, length)
	cvLengths := make([]int, length)

	wg := StartParallelize(length)
	for i := range data {
		go func(i int) {
			var err error
			bb[i], cvLengths[i], err = data[i].ToBytes()
			wg.Done(err)
		}(i)
	}
	if err := EndParallelize(wg); err != nil {
		return nil, nil, err
	}

	for _, v := range bb {
		b = append(b, v...)
	}
	return b, libunlynxtools.UnsafeCastIntsToBytes(cvLengths), nil
}

// FromBytesToArrayCipherVector converts bytes to an array of CipherVector
func FromBytesToArrayCipherVector(data []byte, cvLengthsByte []byte) ([]CipherVector, error) {
	cvLengths := libunlynxtools.UnsafeCastBytesToInts(cvLengthsByte)
	dataConverted := make([]CipherVector, len(cvLengths))
	elementSize := CipherTextByteSize()

	wg := StartParallelize(uint(len(cvLengths)))

	// iter over each value in the flatten data byte array
	bytePos := 0
	for i := range cvLengths {
		nextBytePos := bytePos + cvLengths[i]*elementSize

		cv := make(CipherVector, cvLengths[i])
		v := data[bytePos:nextBytePos]

		go func(v []byte, i int) {
			err := cv.FromBytes(v, cvLengths[i])
			defer wg.Done(err)

			dataConverted[i] = cv
		}(v, i)

		// advance pointer
		bytePos = nextBytePos
	}
	if err := EndParallelize(wg); err != nil {
		return nil, err
	}

	return dataConverted, nil
}

// CipherTextByteSize return the length of one CipherText element transform into []byte
func CipherTextByteSize() int {
	return 2 * SuiTe.PointLen()
}
