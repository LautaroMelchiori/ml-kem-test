package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"testing"
	"text/tabwriter"
)

// Primo seguro de 2048 bits del estándar RFC 3526 (Grupo MODP 14) con generador g = 2
const rfc3526PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

var (
	dhP, _ = new(big.Int).SetString(rfc3526PrimeHex, 16)
	dhG    = big.NewInt(2)
)

// Operaciones de FFDH-2048 (Exponenciación modular en Z_p*)
func generateFFDHKeyPair() (*big.Int, *big.Int, error) {
	privKey, err := rand.Int(rand.Reader, dhP)
	if err != nil {
		return nil, nil, err
	}
	pubKey := new(big.Int).Exp(dhG, privKey, dhP)
	return privKey, pubKey, nil
}

func computeFFDHSharedSecret(privKey, peerPubKey *big.Int) *big.Int {
	return new(big.Int).Exp(peerPubKey, privKey, dhP)
}

// Renderizador de barras ASCII proporcionales para la terminal
func makeBar(value, maxVal float64, maxWidth int) string {
	if maxVal <= 0 || value <= 0 {
		return ""
	}
	filled := int(math.Round((value / maxVal) * float64(maxWidth)))
	if filled == 0 && value > 0 {
		filled = 1
	}
	if filled > maxWidth {
		filled = maxWidth
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", maxWidth-filled)
}

type benchEntry struct {
	Algo     string
	Phase    string
	Result   testing.BenchmarkResult
	MicroSec float64
	OpsSec   float64
}

// TestReporteComparativo ejecuta las mediciones e imprime tablas y gráficos legibles
func TestReporteComparativo(t *testing.T) {
	// 1. Obtención de tamaños reales de estructuras
	privFFDH, pubFFDH, _ := generateFFDHKeyPair()
	secFFDH := computeFFDHSharedSecret(privFFDH, pubFFDH)

	curve := ecdh.X25519()
	privX, _ := curve.GenerateKey(rand.Reader)
	pubX := privX.PublicKey()

	priv768, _ := mlkem.GenerateKey768()
	pub768 := priv768.EncapsulationKey()
	sec768, ct768 := pub768.Encapsulate()

	priv1024, _ := mlkem.GenerateKey1024()
	pub1024 := priv1024.EncapsulationKey()
	sec1024, ct1024 := pub1024.Encapsulate()

	line := strings.Repeat("=", 118)
	subline := strings.Repeat("-", 118)

	// ==================== SECCION 1: TABLA DE TAMAÑOS ====================
	fmt.Println("\n" + line)
	fmt.Println(" 1. COMPARATIVA ARQUITECTURAL Y DE TAMAÑOS EN MEMORIA / RED (BYTES)")
	fmt.Println(line)

	w1 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w1, "Algoritmo\tProblema Matematico\tClave Pub (pk)\tClave Priv (sk)\tRespuesta (msg/c)\tTotal Red (pk+c)\tSecreto (K)\tPost-Cuantico")
	fmt.Fprintln(w1, "---------\t-------------------\t--------------\t---------------\t-----------------\t----------------\t-----------\t-------------")

	ffdhWire := len(pubFFDH.Bytes()) * 2
	x25519Wire := len(pubX.Bytes()) * 2
	kem768Wire := len(pub768.Bytes()) + len(ct768)
	kem1024Wire := len(pub1024.Bytes()) + len(ct1024)

	fmt.Fprintf(w1, "FFDH-2048\tDLP en Grupo Modular Zp*\t%d B\t%d B\t%d B (pk_B)\t%d B\t%d B (bruto)\tNO (Shor)\n",
		len(pubFFDH.Bytes()), len(privFFDH.Bytes()), len(pubFFDH.Bytes()), ffdhWire, len(secFFDH.Bytes()))
	fmt.Fprintf(w1, "X25519\tECDLP en Curve25519\t%d B\t%d B\t%d B (pk_B)\t%d B\t%d B\tNO (Shor)\n",
		len(pubX.Bytes()), len(privX.Bytes()), len(pubX.Bytes()), x25519Wire, len(pubX.Bytes()))
	fmt.Fprintf(w1, "ML-KEM-768\tModule-LWE (Reticulados k=3)\t%d B\t%d B\t%d B (capsula)\t%d B\t%d B\tSI (FIPS 203)\n",
		len(pub768.Bytes()), len(priv768.Bytes()), len(ct768), kem768Wire, len(sec768))
	fmt.Fprintf(w1, "ML-KEM-1024\tModule-LWE (Reticulados k=4)\t%d B\t%d B\t%d B (capsula)\t%d B\t%d B\tSI (FIPS 203)\n",
		len(pub1024.Bytes()), len(priv1024.Bytes()), len(ct1024), kem1024Wire, len(sec1024))
	w1.Flush()

	// ==================== SECCION 2: GRAFICO DE TRAFICO EN RED ====================
	fmt.Println("\n" + subline)
	fmt.Println(" GRAFICO 1: IMPACTO EN RED - BYTES TOTALES TRANSMITIDOS EN EL HANDSHAKE (Clave Publica + Respuesta/Capsula)")
	fmt.Println(subline)

	maxWire := float64(kem1024Wire)
	wireData := []struct {
		name  string
		bytes int
	}{
		{"X25519 (ECDH)", x25519Wire},
		{"FFDH-2048 (Modular)", ffdhWire},
		{"ML-KEM-768 (PQC)", kem768Wire},
		{"ML-KEM-1024 (PQC)", kem1024Wire},
	}

	for _, d := range wireData {
		bar := makeBar(float64(d.bytes), maxWire, 45)
		ratio := float64(d.bytes) / float64(x25519Wire)
		fmt.Printf(" %-20s [%s] %5d Bytes  (%4.1fx vs X25519)\n", d.name, bar, d.bytes, ratio)
	}

	// ==================== SECCION 3: EJECUCION DE BENCHMARKS ====================
	fmt.Println("\n[*] Ejecutando microbenchmarks de CPU y memoria (esto toma unos segundos)...")

	tests := []struct {
		algo  string
		phase string
		fn    func(b *testing.B)
	}{
		{"FFDH-2048", "1. KeyGen (g^a mod p)", BenchmarkFFDH2048_KeyGen},
		{"FFDH-2048", "2. Emisor (B^a mod p)", BenchmarkFFDH2048_Agreement},
		{"FFDH-2048", "3. Receptor (A^b mod p)", BenchmarkFFDH2048_Agreement},

		{"X25519", "1. KeyGen ([a]G)", BenchmarkX25519_KeyGen},
		{"X25519", "2. Emisor ([a]Pub_B)", BenchmarkX25519_Agreement},
		{"X25519", "3. Receptor ([b]Pub_A)", BenchmarkX25519_Agreement},

		{"ML-KEM-768", "1. KeyGen (Matriz k=3)", BenchmarkMLKEM768_KeyGen},
		{"ML-KEM-768", "2. Emisor (Encapsulate)", BenchmarkMLKEM768_Encaps},
		{"ML-KEM-768", "3. Receptor (Decaps+FO)", BenchmarkMLKEM768_Decaps},

		{"ML-KEM-1024", "1. KeyGen (Matriz k=4)", BenchmarkMLKEM1024_KeyGen},
		{"ML-KEM-1024", "2. Emisor (Encapsulate)", BenchmarkMLKEM1024_Encaps},
		{"ML-KEM-1024", "3. Receptor (Decaps+FO)", BenchmarkMLKEM1024_Decaps},
	}

	var results []benchEntry
	totalsByAlgo := make(map[string]float64)

	for _, tc := range tests {
		res := testing.Benchmark(tc.fn)
		us := float64(res.NsPerOp()) / 1000.0
		ops := 1e9 / float64(res.NsPerOp())
		results = append(results, benchEntry{
			Algo:     tc.algo,
			Phase:    tc.phase,
			Result:   res,
			MicroSec: us,
			OpsSec:   ops,
		})
		totalsByAlgo[tc.algo] += us
	}

	// ==================== SECCION 4: TABLA DE RENDIMIENTO ====================
	fmt.Println("\n" + line)
	fmt.Println(" 2. RESULTADOS DE RENDIMIENTO DE CPU Y ASIGNACION DE MEMORIA")
	fmt.Println(line)
	fmt.Println(" Glosario de columnas:")
	fmt.Println("  - Iteraciones (N)  : Veces que se ejecuto la funcion para estabilizar la muestra estadistica.")
	fmt.Println("  - Latencia (us/op) : Tiempo promedio de CPU por operacion en microsegundos (1 ms = 1000 us).")
	fmt.Println("  - Throughput       : Cantidad maxima de operaciones por segundo en un unico nucleo.")
	fmt.Println("  - Memoria (B/op)   : Bytes reservados dinamicamente en el Heap por cada ejecucion.")
	fmt.Println("  - Allocs/op        : Cantidad de llamadas al gestor de memoria (menor valor = menor presion al GC).")
	fmt.Println(subline)

	w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w2, "Algoritmo\tFase de la Operacion\tIteraciones (N)\tLatencia (us/op)\tThroughput (ops/s)\tMemoria (B/op)\tAllocs/op")
	fmt.Fprintln(w2, "---------\t--------------------\t---------------\t----------------\t------------------\t--------------\t---------")

	for _, r := range results {
		fmt.Fprintf(w2, "%s\t%s\t%10d\t%10.2f us\t%12.0f /s\t%8d B\t%6d\n",
			r.Algo, r.Phase, r.Result.N, r.MicroSec, r.OpsSec, r.Result.AllocedBytesPerOp(), r.Result.AllocsPerOp())
	}
	w2.Flush()

	// ==================== SECCION 5: GRAFICOS DE RENDIMIENTO ====================
	fmt.Println("\n" + subline)
	fmt.Println(" GRAFICO 2A: TIEMPO TOTAL DE CPU POR INTERCAMBIO COMPLETO (KeyGen + Emisor + Receptor) - ESCALA GLOBAL")
	fmt.Println(subline)

	algosOrder := []string{"FFDH-2048", "X25519", "ML-KEM-768", "ML-KEM-1024"}
	maxTotal := 0.0
	for _, a := range algosOrder {
		if totalsByAlgo[a] > maxTotal {
			maxTotal = totalsByAlgo[a]
		}
	}

	for _, a := range algosOrder {
		tot := totalsByAlgo[a]
		bar := makeBar(tot, maxTotal, 45)
		ratio := tot / totalsByAlgo["X25519"]
		fmt.Printf(" %-14s [%s] %8.2f us  (%5.1fx vs X25519)\n", a, bar, tot, ratio)
	}

	fmt.Println("\n" + subline)
	fmt.Println(" GRAFICO 2B: ZOOM DE ALTA VELOCIDAD (Excluyendo FFDH-2048 para apreciar diferencias en microsegundos)")
	fmt.Println(subline)

	maxFast := 0.0
	for _, r := range results {
		if r.Algo != "FFDH-2048" && r.MicroSec > maxFast {
			maxFast = r.MicroSec
		}
	}

	currentAlgo := ""
	for _, r := range results {
		if r.Algo == "FFDH-2048" {
			continue
		}
		if r.Algo != currentAlgo {
			if currentAlgo != "" {
				fmt.Println()
			}
			currentAlgo = r.Algo
		}
		bar := makeBar(r.MicroSec, maxFast, 45)
		fmt.Printf(" %-12s | %-23s [%s] %6.2f us\n", r.Algo, r.Phase, bar, r.MicroSec)
	}
	fmt.Println(line + "\n")
}

// ==================== FUNCIONES DE BENCHMARK ESTANDAR ====================

func BenchmarkFFDH2048_KeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = generateFFDHKeyPair()
	}
}

func BenchmarkFFDH2048_Agreement(b *testing.B) {
	privA, _, _ := generateFFDHKeyPair()
	_, pubB, _ := generateFFDHKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeFFDHSharedSecret(privA, pubB)
	}
}

func BenchmarkX25519_KeyGen(b *testing.B) {
	curve := ecdh.X25519()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = curve.GenerateKey(rand.Reader)
	}
}

func BenchmarkX25519_Agreement(b *testing.B) {
	curve := ecdh.X25519()
	privA, _ := curve.GenerateKey(rand.Reader)
	privB, _ := curve.GenerateKey(rand.Reader)
	pubB := privB.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = privA.ECDH(pubB)
	}
}

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

func BenchmarkMLKEM1024_KeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mlkem.GenerateKey1024()
	}
}

func BenchmarkMLKEM1024_Encaps(b *testing.B) {
	priv, _ := mlkem.GenerateKey1024()
	pub := priv.EncapsulationKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pub.Encapsulate()
	}
}

func BenchmarkMLKEM1024_Decaps(b *testing.B) {
	priv, _ := mlkem.GenerateKey1024()
	pub := priv.EncapsulationKey()
	_, ct := pub.Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Decapsulate(ct)
	}
}