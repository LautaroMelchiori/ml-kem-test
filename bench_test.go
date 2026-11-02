package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestSizes imprime los tamaños en bytes de las estructuras de datos
func TestSizes(t *testing.T) {
	// X25519
	curve := ecdh.X25519()
	privECDH, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generando X25519: %v", err)
	}
	pubECDH := privECDH.PublicKey()

	// ML-KEM-768
	privKEM, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("Error generando ML-KEM-768: %v", err)
	}
	pubKEM := privKEM.EncapsulationKey()
	_, ciphertext := pubKEM.Encapsulate()

	fmt.Println("\n================= COMPARATIVA DE TAMAÑOS (BYTES) =================")
	fmt.Printf("X25519:     Clave Pública: %4d B | Clave Privada: %4d B | Secreto:  %4d B\n",
		len(pubECDH.Bytes()), len(privECDH.Bytes()), len(pubECDH.Bytes()))
	fmt.Printf("ML-KEM-768: Clave Pública: %4d B | Clave Privada: %4d B | Cápsula:  %4d B\n",
		len(pubKEM.Bytes()), len(privKEM.Bytes()), len(ciphertext))
	fmt.Println("==================================================================")
}

// Benchmarks X25519
func BenchmarkX25519_KeyGen(b *testing.B) {
	curve := ecdh.X25519()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = curve.GenerateKey(rand.Reader)
	}
}

func BenchmarkX25519_SharedSecret(b *testing.B) {
	curve := ecdh.X25519()
	privA, _ := curve.GenerateKey(rand.Reader)
	privB, _ := curve.GenerateKey(rand.Reader)
	pubB := privB.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = privA.ECDH(pubB)
	}
}

// Benchmarks ML-KEM-768
func BenchmarkMLKEM768_KeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mlkem.GenerateKey768()
	}
}

func BenchmarkMLKEM768_Encaps(b *testing.B) {
	priv, _ := mlkem.GenerateKey768()
	pub := priv.EncapsulationKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pub.Encapsulate()
	}
}

func BenchmarkMLKEM768_Decaps(b *testing.B) {
	priv, _ := mlkem.GenerateKey768()
	pub := priv.EncapsulationKey()
	_, ct := pub.Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Decapsulate(ct)
	}
}