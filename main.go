package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// StandardECDSA Implementation
type StandardECDSA struct {
	privateKey *ecdsa.PrivateKey
}

func NewStandardECDSA() (*StandardECDSA, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	return &StandardECDSA{
		privateKey: privateKey,
	}, nil
}

func (e *StandardECDSA) Sign(message []byte) (r, s *big.Int, err error) {
	// Hash the message first as per Ethereum's signing scheme
	hash := crypto.Keccak256Hash(message)

	// Sign the hash
	signature, err := crypto.Sign(hash.Bytes(), e.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign: %v", err)
	}

	// Extract r, s from the signature
	r = new(big.Int).SetBytes(signature[:32])
	s = new(big.Int).SetBytes(signature[32:64])

	return r, s, nil
}

func (e *StandardECDSA) Verify(message []byte, r, s *big.Int) bool {
	hash := crypto.Keccak256Hash(message)

	// Convert r, s to signature format
	signature := make([]byte, 65)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:64])

	// Recover the public key and verify
	pubKeyBytes := crypto.FromECDSAPub(&e.privateKey.PublicKey)
	return crypto.VerifySignature(pubKeyBytes, hash.Bytes(), signature[:64])
}

// ModifiedECDSA Implementation with pre-value x
type ModifiedECDSA struct {
	x  []byte            // Pre-value x
	sk *ecdsa.PrivateKey // Secret key derived from H(x)
}

func NewModifiedECDSA(preValue []byte) (*ModifiedECDSA, error) {
	// Calculate sk = H(x)
	h := sha256.New()
	h.Write(preValue)
	skBytes := h.Sum(nil)

	// Convert hash to private key
	sk, err := crypto.ToECDSA(common.LeftPadBytes(skBytes, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %v", err)
	}

	return &ModifiedECDSA{
		x:  preValue,
		sk: sk,
	}, nil
}

func (e *ModifiedECDSA) Sign(message []byte) (r, s *big.Int, err error) {
	// Calculate k = H(x, m)
	h := sha256.New()
	h.Write(e.x)
	h.Write(message)
	k := h.Sum(nil)

	// Hash the message
	messageHash := crypto.Keccak256Hash(message)

	// We'll use the k value as a deterministic component in the signature
	// Note: In a real implementation, you'd want to ensure k is properly generated
	finalHash := crypto.Keccak256Hash(k, messageHash.Bytes())

	signature, err := crypto.Sign(finalHash.Bytes(), e.sk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign: %v", err)
	}

	// Extract r, s from the signature
	r = new(big.Int).SetBytes(signature[:32])
	s = new(big.Int).SetBytes(signature[32:64])

	return r, s, nil
}

func (e *ModifiedECDSA) Verify(message []byte, r, s *big.Int) bool {
	// Hash the message
	messageHash := crypto.Keccak256Hash(message)

	// Calculate k = H(x, m)
	h := sha256.New()
	h.Write(e.x)
	h.Write(message)
	k := h.Sum(nil)

	// Combine k with message hash
	finalHash := crypto.Keccak256Hash(k, messageHash.Bytes())

	// Convert r, s to signature format
	signature := make([]byte, 65)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:64])

	// Get public key bytes
	pubKeyBytes := crypto.FromECDSAPub(&e.sk.PublicKey)

	return crypto.VerifySignature(pubKeyBytes, finalHash.Bytes(), signature[:64])
}

func main() {
	// Example usage of Standard ECDSA
	standardEcdsa, err := NewStandardECDSA()
	if err != nil {
		fmt.Printf("Error creating standard ECDSA: %v\n", err)
		return
	}

	message := []byte("Hello, World!")
	r, s, err := standardEcdsa.Sign(message)
	if err != nil {
		fmt.Printf("Error signing with standard ECDSA: %v\n", err)
		return
	}

	valid := standardEcdsa.Verify(message, r, s)
	fmt.Printf("Standard ECDSA signature valid: %v\n", valid)

	// Example usage of Modified ECDSA
	preValue := []byte("some random pre-value")
	modifiedEcdsa, err := NewModifiedECDSA(preValue)
	if err != nil {
		fmt.Printf("Error creating modified ECDSA: %v\n", err)
		return
	}

	r, s, err = modifiedEcdsa.Sign(message)
	if err != nil {
		fmt.Printf("Error signing with modified ECDSA: %v\n", err)
		return
	}

	valid = modifiedEcdsa.Verify(message, r, s)
	fmt.Printf("Modified ECDSA signature valid: %v\n", valid)
}
