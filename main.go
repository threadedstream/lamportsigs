package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"reflect"
)

const (
	pairsNum = 256
)

type Signature [256][32]uint8

type Pair struct {
	First  [32]uint8
	Second [32]uint8
}

type PrivateKey struct {
	Key [256]Pair
}

type PublicKey struct {
	Key [512][32]uint8
}

type KeyPair struct {
	Private PrivateKey
	Public  PublicKey
}

func GenerateKeys() (*KeyPair, error) {
	pair := KeyPair{}
	for i := range pairsNum {
		pair.Private.Key[i] = Pair{
			First:  generateRandom256Num(),
			Second: generateRandom256Num(),
		}
	}

	j := 0
	for i := range pairsNum {
		pair.Public.Key[j] = sha256.Sum256(pair.Private.Key[i].First[:])
		pair.Public.Key[j+1] = sha256.Sum256(pair.Private.Key[i].Second[:])
		j += 2
	}

	return &pair, nil
}

func Sign(message []byte, key PrivateKey) Signature {
	messageSum := sha256.Sum256(message)

	var signature Signature
	signatureIdx := 0

	for _, b := range messageSum {
		for range 8 {
			if b&1 == 0 {
				signature[signatureIdx] = key.Key[signatureIdx].First
			} else {
				signature[signatureIdx] = key.Key[signatureIdx].Second
			}
			signatureIdx++
			b >>= 1
		}
	}

	return signature
}

func Verify(message []byte, signature Signature, key PublicKey) bool {
	messageSum := sha256.Sum256(message)

	var resultSig Signature
	var signatureIdx, resultSigIdx int

	for _, b := range messageSum {
		for range 8 {
			if b&1 == 0 {
				resultSig[resultSigIdx] = key.Key[signatureIdx]
			} else {
				resultSig[resultSigIdx] = key.Key[signatureIdx+1]
			}
			signatureIdx += 2
			resultSigIdx += 1
			b >>= 1
		}
	}

	// hash each of the 256 random numbers in alice's signature
	var hashedSignature Signature
	for i, num := range signature {
		hashedSignature[i] = sha256.Sum256(num[:])
	}

	return reflect.DeepEqual(resultSig, hashedSignature)
}

func generateRandom256Num() (num [32]uint8) {
	a, b, c, d := rand.Int63(), rand.Int63(), rand.Int63(), rand.Int63()
	enc := binary.BigEndian

	enc.PutUint64(num[0:8], uint64(a))
	enc.PutUint64(num[8:16], uint64(b))
	enc.PutUint64(num[16:24], uint64(c))
	enc.PutUint64(num[24:32], uint64(d))

	return num
}

func main() {
	keyPair, err := GenerateKeys()
	if err != nil {
		log.Fatal(err)
	}
	message := []byte("test message")
	sig := Sign(message, keyPair.Private)
	fmt.Println(Verify(message, sig, keyPair.Public))
}
