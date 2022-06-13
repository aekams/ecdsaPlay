package ecdsaplay

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math"
	"math/big"
)

// Per-Message secret number generation using extra random bits
// as described in Federal Information Processing Standard Publication
// (FIPS PUB 186-4) Digital Signature Standard (DSS) issued July 2013
func GeneratePreMessageSecret(eC elliptic.Curve) (k *big.Int, err error) {

	// Initializing slice of bytes based on len(n)+64 bits
	var sliceOfRandomNumbers = make([]byte, (eC.Params().N.BitLen()+64)/8)

	// Golang cryptographically secure random number generation
	_, err = rand.Read(sliceOfRandomNumbers)

	if err != nil {
		return nil, err
	}

	c := ConcatenateBytes(sliceOfRandomNumbers)

	k = new(big.Int)
	var one = big.NewInt(int64(1))

	// Calculating k in accordance with step 6 and 7 of B.5.1 of
	// Federal Information Processing Standard Publication (FIPS PUB 186-4)
	// Digital Signature Standard (DSS) issued July 2013
	k.Mod(c, new(big.Int).Sub(eC.Params().N, one))
	k.Add(k, big.NewInt(int64(1)))

	if k.Cmp(one) == 1 || k.Cmp(new(big.Int).Sub(eC.Params().N, one)) == -1 {
		return k, nil
	}

	return nil, errors.New("Error: Invalid k, outside of the order of group, N")

}

type Key struct {
	Private          *big.Int
	PublicX, PublicY *big.Int
	Curve            elliptic.Curve
}

// Generates Public/Private key pair in accordance with elliptic curve
// scalar multiplication
func GeneratePrivatePublicKeyPair(eC elliptic.Curve) (key Key, err error) {
	key.Curve = eC
	// Calling Per-Message secret number generation to assign value of k
	// as private key
	key.Private, err = GeneratePreMessageSecret(eC)
	if err != nil {
		return key, err
	}

	key.PublicX, key.PublicY = eC.ScalarBaseMult(key.Private.Bytes())
	return key, nil

}

// Signature = (r, s); where, r is the x-coordinate of the R which is calculated as kG
// and k itself is selected randomly and s = (z + re)/k; where, z is hash of the message
// to be signed and e = private key
func Sign(key Key, messageHash []byte) (r, s *big.Int, err error) {
	privateKey := key.Private
	var randomK *big.Int
	r = new(big.Int)
	var re = new(big.Int)
	s = new(big.Int)

	// Calling Per-Message secret number generation to assign value of k
	// as a random number
	randomK, err = GeneratePreMessageSecret(key.Curve)

	if err != nil {
		return nil, nil, err
	}

	// r = kG (x-coordinate only)
	r, _ = key.Curve.ScalarBaseMult(randomK.Bytes())

	// s = (z + re)
	s = s.Add(ConcatenateBytes(messageHash), re.Mul(privateKey, r))

	var invK = inverse(randomK, key.Curve.Params().N)
	s = s.Mul(s, invK)
	s = s.Mod(s, key.Curve.Params().N)

	return r, s, nil
}

// Verification is based on validation of r.
// u = z/s and v = r/s are calculated
// Signature is valid if x-axis of r calculated from uG + vP = R
// is equal to the r included in signature
func Verify(r, s, publicKeyX, publicKeyY *big.Int, curve elliptic.Curve, messageHash []byte) bool {
	z := ConcatenateBytes(messageHash)

	var u = new(big.Int)
	var v = new(big.Int)

	var invS = inverse(s, curve.Params().N)

	// u = z/s and v = r/s
	u = u.Mul(z, invS)
	u = u.Mod(u, curve.Params().N)
	v = v.Mul(r, invS)
	v = v.Mod(v, curve.Params().N)

	// uG and vP
	var uGx, uGy *big.Int
	var vPx, vPy *big.Int
	uGx, uGy = curve.ScalarBaseMult(u.Bytes())
	vPx, vPy = curve.ScalarMult(publicKeyX, publicKeyY, v.Bytes())

	// r = uG + vP (x-coordinate only)
	calRx, _ := curve.Add(uGx, uGy, vPx, vPy)

	// fmt.Println("Signature r = ", r)
	// fmt.Println("Calculated r = ", calRx)

	return calRx.Cmp(r) == 0
}

// Converts byte(s) stored in slice of data as a single concatenated big Int value
func ConcatenateBytes(bytes []byte) *big.Int {
	// Initializing non-negative random integer c as golang big.Int
	var c = new(big.Int)

	for i := len(bytes) - 1; i >= 0; i-- {

		// Iterating through slice of random bytes as golang big.Int
		var randomByte = big.NewInt(int64(bytes[i]))

		// Dynamic offset used to help concatenate all elements as a single big.Int value
		var offset = new(big.Int)
		offset.Exp(big.NewInt(int64(1000)), big.NewInt(int64(int(math.Abs(float64(i-len(bytes))+1)))), big.NewInt(int64(0)))

		// non-negative random integer c being concatenated from elements of slice
		c.Add(c, new(big.Int).Mul(randomByte, offset))
	}
	return c
}

// Calculates inverse in accordance with Fermat Little theorm
// d^-1 = d^(prime-2); where d is denominator to be inversed
func inverse(d *big.Int, prime *big.Int) *big.Int {
	var invResult = new(big.Int)
	var exponent = new(big.Int)
	exponent = exponent.Sub(prime, big.NewInt(2))
	invResult = invResult.Exp(d, exponent, prime)
	return invResult
}
