# ecdsaPlay
Implementation of Elliptic Curve Digital Signature Algorithm in Golang

**The Basics**

In general, an elliptic curve takes the form of y^2 = x^3 + ax + b. An example of this plotted over real numbers on cartesian x-y coordinates is shown 

![Elliptic Curve](Reference%20Images/Elliptic_Curve.png).

Point ‘addition’ (or operation) on this curve is defined when a line crossing two points, to be added, intersects a third point on the curve. Addition is simply the third point reflected over x-axis. Point addition (or operation) can be performed when P1 = P2 and P1 != P2. The operation itself satisfies Identity, Commutativity, Associativity, and Invertibility.

An elliptic curve over infinite ‘real numbers’ is not practical or feasible. Instead, a very large finite field is used. The order of a set (or the curve) is a very large prime number. Modulo (or clock) arithmetic is used to ensure that the results of the operation are within the finite field. The result is a scatter plot with symmetry around the middle.

**Curve for Bitcoin**

Bitcoin uses secp256k1 which is defined as y^2 = x^3 + ax + b, where a = 0, b = 7 and a very larger prime number, p = 2^256 – 2^32 - 977. Bitcoin’s actual curve is defined over a finite field as noted above and hence has random scatter points. This implementation yields asymmetric relationship P = eG with discrete log difficulty to compute e from P and G.

**The Implementation**

Elliptic Curve Digital Signature Algorithm (ECDSA) has three (3) primary components:

1. Generation of cryptographically secure private/public key pair 
2. Signing of a message and generation of appropriate signature components
3. Verification of a signature

The figure below shows the graphical representation of this implementation in Go.

![ecdsaPlay Implementation](Reference%20Images/ecdsaPlayImplementation.png).

**Component 1: Private/Public Key Pair**

Function titled *GeneratePrivatePublicKeyPair* takes a standard implementation of Go's elliptic curve as its input and returns a struct that includes public address and private key pair. To generate private key, the function calls *GeneratePreMessageSecrete* which uses extra random bits as described in Federal Information Processing Standard Publication (FIPS PUB 186-4) Digital Signature Standard (DSS) issued July 2013. It allocates multiple byte-size memory based on the bit length of the order of the curve (i.e., N)  + 64 additional random bits. Go's rand.Read fills the allocated memory with cryptographically secure random number generation. For example, using secp256r1, 40 bytes of memory space gets allocated. Each byte contains a random number between 0 and 255.

Helper function titled *ConcatenateBytes* creates a single big.Int value (i.e., labeled as c) based on the sequential order of the slice of 40 bytes. The function performs this operation as per the following logic:

SIGMA(i = 0 to Len-1) -> Byte[i]*(1000)^(i-Len+1)

In accordance with step 6 and 7 of B.5.1 of Federal Information Processing Standard Publication (FIPS PUB 186-4) Digital Signature Standard (DSS) issued July 2013, final result (i.e., Private key 'k') is determined by calculating:

k = (c % (N-1)) + 1

Public key is calculated by performing scalar multiplication operation over elliptic curve with Generator Point 'G' over 'k' times.

**Component 2: Signature**

A signature has two output values (r, s), where r is the x-coordinate of R which is calculated as kG and k itself is selected randomly. s = (z + re)/k, where 'z' is the hash of a message to be signed and 'e' is the private key.

*Sign* function takes a Key and a hashed message as its input. *GeneratePreMessageSecrete* is called to calculate a random value 'randomK.' Scalar multiplication over the elliptic curve associated with private key 'e' (note e = k from discussion under Component 1) with Generator Point 'G' over 'e' times will result in R, where 'r' is the x-coordinate of this output.

The calculation of s = (z + re)/k utilizes a helper function. Specifically, implementation of Fermat Little Theorem is used to determine inverse of 'randomK.' The helper function determines inverse of an input by calculating input^(prime-2) % prime, where prime is the order of the elliptic curve 'N'.

**Component 3: Verification**

Verification is based on validation of 'r' included as one of the outputs of the original signature. *Verify* function calculates

u = (z*s^-1) % N

v = (r*s^-1) % N

Finally R is determined by performing scalar multiplication operation over the elliptic curve with Generator Point 'G' over 'u' times plus scalar multiplication with Public Address over 'v' times.

uG + vP = R, where r is the x-coordinate of the result.

The function compares 'r' from the output of the signature, to 'r' calculated as noted above and returns true if the result matches.

**References**

[1] Federal Information Processing Standard Publication (FIPS PUB 186-4) Digital Signature Standard (DSS), July 2013

[2] Jimmy Song: Programing Bitcoin, 2019

[3] Andreas M. Antonopoulos: Mastering Bitcoin, 2018
