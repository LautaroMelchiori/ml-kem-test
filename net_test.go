package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"
)

const ethernetMSS = 1460 // MTU 1500B - 20B IPv4 - 20B TCP

// Wrapper de net.Conn para interceptar y medir bytes exactos en el socket TCP
type meteredConn struct {
	net.Conn
	bytesWritten      int64
	bytesRead         int64
	writeCalls        int64
	firstWritePayload int64
}

func (m *meteredConn) Write(b []byte) (int, error) {
	n, err := m.Conn.Write(b)
	if atomic.AddInt64(&m.writeCalls, 1) == 1 {
		atomic.StoreInt64(&m.firstWritePayload, int64(n))
	}
	atomic.AddInt64(&m.bytesWritten, int64(n))
	return n, err
}

func (m *meteredConn) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	atomic.AddInt64(&m.bytesRead, int64(n))
	return n, err
}

func makeNetBar(value, maxVal float64, maxWidth int) string {
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

func calcTCPSegments(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	return int(math.Ceil(float64(bytes) / float64(ethernetMSS)))
}

// Lectura y escritura con prefijo de longitud (2 bytes uint16) para framing TCP puro
func writeFrame(w io.Writer, data []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// Cifrado simétrico autenticado AES-256-GCM tras acordar la clave K
func sendAESGCM(w io.Writer, rawKey, plaintext []byte) error {
	key := sha256.Sum256(rawKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return writeFrame(w, ciphertext)
}

func recvAESGCM(r io.Reader, rawKey []byte) ([]byte, error) {
	frame, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(rawKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	return aead.Open(nil, frame[:ns], frame[ns:], nil)
}

// ==================== 1. HANDSHAKE TCP PURO (X25519 vs ML-KEM-768 vs ML-KEM-1024) ====================

type rawNetMetrics struct {
	Name            string
	ClientToSrvB    int
	SrvToClientB    int
	TotalHandshakeB int
	ClientSegments  int
	ServerSegments  int
	AvgLatencyUs    float64
}

func runRawTCPExperiment(name, mode string, iterations int) (rawNetMetrics, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return rawNetMetrics{}, err
	}
	defer ln.Close()

	// Goroutine del Servidor TCP
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var sharedKey []byte

				switch mode {
				case "X25519":
					curve := ecdh.X25519()
					privS, _ := curve.GenerateKey(rand.Reader)
					pubCBytes, err := readFrame(c)
					if err != nil {
						return
					}
					pubC, _ := curve.NewPublicKey(pubCBytes)
					_ = writeFrame(c, privS.PublicKey().Bytes())
					sharedKey, _ = privS.ECDH(pubC)

				case "ML-KEM-768":
					pubBytes, err := readFrame(c)
					if err != nil {
						return
					}
					pub, _ := mlkem.NewEncapsulationKey768(pubBytes)
					var ct []byte
					sharedKey, ct = pub.Encapsulate()
					_ = writeFrame(c, ct)

				case "ML-KEM-1024":
					pubBytes, err := readFrame(c)
					if err != nil {
						return
					}
					pub, _ := mlkem.NewEncapsulationKey1024(pubBytes)
					var ct []byte
					sharedKey, ct = pub.Encapsulate()
					_ = writeFrame(c, ct)
				}

				// Verificación del canal leyendo mensaje cifrado con AES-256-GCM
				_, _ = recvAESGCM(c, sharedKey)
			}(conn)
		}
	}()

	var totalDuration time.Duration
	var c2sBytes, s2cBytes int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		rawConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return rawNetMetrics{}, err
		}
		mc := &meteredConn{Conn: rawConn}

		var sharedKey []byte
		switch mode {
		case "X25519":
			curve := ecdh.X25519()
			privC, _ := curve.GenerateKey(rand.Reader)
			_ = writeFrame(mc, privC.PublicKey().Bytes())
			pubSBytes, _ := readFrame(mc)
			pubS, _ := curve.NewPublicKey(pubSBytes)
			sharedKey, _ = privC.ECDH(pubS)

		case "ML-KEM-768":
			privC, _ := mlkem.GenerateKey768()
			_ = writeFrame(mc, privC.EncapsulationKey().Bytes())
			ct, _ := readFrame(mc)
			sharedKey, _ = privC.Decapsulate(ct)

		case "ML-KEM-1024":
			privC, _ := mlkem.GenerateKey1024()
			_ = writeFrame(mc, privC.EncapsulationKey().Bytes())
			ct, _ := readFrame(mc)
			sharedKey, _ = privC.Decapsulate(ct)
		}

		// Capturamos los bytes exactos del intercambio de claves antes de enviar datos de aplicación
		if i == 0 {
			c2sBytes = int(mc.bytesWritten)
			s2cBytes = int(mc.bytesRead)
		}

		_ = sendAESGCM(mc, sharedKey, []byte("PING_UTN_CRIPTO"))
		mc.Close()
		totalDuration += time.Since(start)
	}

	return rawNetMetrics{
		Name:            name,
		ClientToSrvB:    c2sBytes,
		SrvToClientB:    s2cBytes,
		TotalHandshakeB: c2sBytes + s2cBytes,
		ClientSegments:  calcTCPSegments(c2sBytes),
		ServerSegments:  calcTCPSegments(s2cBytes),
		AvgLatencyUs:    float64(totalDuration.Microseconds()) / float64(iterations),
	}, nil
}

// ==================== 2. HANDSHAKE TLS 1.3 REAL (X25519 vs X25519MLKEM768) ====================

type tlsNetMetrics struct {
	Name            string
	CurveID         tls.CurveID
	ClientHelloB    int
	ClientTotalB    int
	ServerTotalB    int
	TotalHandshakeB int
	ClientHelloSegs int
	ServerFlightSeg int
	AvgLatencyUs    float64
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{Organization: []string{"UTN FRBA - Criptografia PQC"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func runTLS13Experiment(name string, curve tls.CurveID, cert tls.Certificate, iterations int) (tlsNetMetrics, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tlsNetMetrics{}, err
	}
	defer ln.Close()

	srvTLSConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{curve},
	}

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsSrv := tls.Server(c, srvTLSConfig)
				if err := tlsSrv.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 4)
				_, _ = io.ReadFull(tlsSrv, buf)
				_, _ = tlsSrv.Write([]byte("PONG"))
			}(rawConn)
		}
	}()

	cliTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{curve},
		ServerName:         "cripto.frba.utn.edu.ar",
	}

	var totalDuration time.Duration
	var clientHelloBytes, clientTotalBytes, serverTotalBytes int

	for i := 0; i < iterations; i++ {
		start := time.Now()
		rawConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return tlsNetMetrics{}, err
		}
		mc := &meteredConn{Conn: rawConn}
		tlsCli := tls.Client(mc, cliTLSConfig)

		// Ejecutamos exclusivamente el Handshake TLS 1.3 para aislar los bytes de control
		if err := tlsCli.Handshake(); err != nil {
			mc.Close()
			return tlsNetMetrics{}, err
		}

		if i == 0 {
			clientHelloBytes = int(mc.firstWritePayload)
			clientTotalBytes = int(mc.bytesWritten)
			serverTotalBytes = int(mc.bytesRead)
		}

		// Verificación de transmisión de datos de aplicación sobre el canal TLS
		_, _ = tlsCli.Write([]byte("PING"))
		reply := make([]byte, 4)
		_, _ = io.ReadFull(tlsCli, reply)

		tlsCli.Close()
		totalDuration += time.Since(start)
	}

	return tlsNetMetrics{
		Name:            name,
		CurveID:         curve,
		ClientHelloB:    clientHelloBytes,
		ClientTotalB:    clientTotalBytes,
		ServerTotalB:    serverTotalBytes,
		TotalHandshakeB: clientTotalBytes + serverTotalBytes,
		ClientHelloSegs: calcTCPSegments(clientHelloBytes),
		ServerFlightSeg: calcTCPSegments(serverTotalBytes),
		AvgLatencyUs:    float64(totalDuration.Microseconds()) / float64(iterations),
	}, nil
}

// ==================== REPORTE PRINCIPAL DE RED ====================

func TestReporteRed(t *testing.T) {
	const iterations = 150
	line := strings.Repeat("=", 120)
	subline := strings.Repeat("-", 120)

	fmt.Println("\n[*] Ejecutando pruebas de red sobre sockets TCP reales (150 conexiones por esquema)...")

	// 1. Ejecución de pruebas sobre TCP Puro (X25519 vs ML-KEM-768 vs ML-KEM-1024)
	rawX25519, err := runRawTCPExperiment("X25519 (ECDH)", "X25519", iterations)
	if err != nil {
		t.Fatalf("Error en TCP X25519: %v", err)
	}
	rawKEM768, err := runRawTCPExperiment("ML-KEM-768 (FIPS 203)", "ML-KEM-768", iterations)
	if err != nil {
		t.Fatalf("Error en TCP ML-KEM-768: %v", err)
	}
	rawKEM1024, err := runRawTCPExperiment("ML-KEM-1024 (FIPS 203)", "ML-KEM-1024", iterations)
	if err != nil {
		t.Fatalf("Error en TCP ML-KEM-1024: %v", err)
	}
	rawResults := []rawNetMetrics{rawX25519, rawKEM768, rawKEM1024}

	// 2. Ejecución de pruebas sobre TLS 1.3 Real
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Error generando certificado X.509: %v", err)
	}
	tlsClassic, err := runTLS13Experiment("TLS 1.3 Clasico (X25519)", tls.X25519, cert, iterations)
	if err != nil {
		t.Fatalf("Error en TLS X25519: %v", err)
	}
	tlsHybrid, err := runTLS13Experiment("TLS 1.3 Hibrido (X25519MLKEM768)", tls.X25519MLKEM768, cert, iterations)
	if err != nil {
		t.Fatalf("Error en TLS X25519MLKEM768: %v", err)
	}
	tlsResults := []tlsNetMetrics{tlsClassic, tlsHybrid}

	// ==================== IMPRESION SECCION 1: CANAL TCP PURO ====================
	fmt.Println("\n" + line)
	fmt.Println(" 1. INTERCAMBIO DE CLAVES PURO SOBRE SOCKETS TCP + CANAL AES-256-GCM (Promedio de 150 conexiones)")
	fmt.Println(line)
	fmt.Println(" Nota: Incluye unicamente los bytes del intercambio de claves en el socket TCP (prefijo de 2B + primitiva)")
	fmt.Println("       y mide cuantos segmentos TCP requiere cada mensaje considerando un MSS Ethernet estandar de 1460 Bytes.")
	fmt.Println(subline)

	w1 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w1, "Esquema\tCliente->Srv (pk)\tSrv->Cliente (c/pk)\tTotal Handshake\tSegs TCP (Cli / Srv)\tLatencia Handshake\tFactor Red vs X25519")
	fmt.Fprintln(w1, "-------\t-----------------\t-------------------\t---------------\t--------------------\t------------------\t--------------------")

	for _, r := range rawResults {
		factor := float64(r.TotalHandshakeB) / float64(rawX25519.TotalHandshakeB)
		fmt.Fprintf(w1, "%s\t%6d Bytes\t%6d Bytes\t%6d Bytes\t%d seg / %d seg\t%8.1f us\t%6.1fx\n",
			r.Name, r.ClientToSrvB, r.SrvToClientB, r.TotalHandshakeB, r.ClientSegments, r.ServerSegments, r.AvgLatencyUs, factor)
	}
	w1.Flush()

	fmt.Println("\n" + subline)
	fmt.Println(" GRAFICO 1: BYTES EN TRANSITO POR DIRECCION FRENTE AL LIMITE DE FRAGMENTACION TCP (MSS = 1460 Bytes)")
	fmt.Println(subline)

	maxRawB := float64(rawKEM1024.ClientToSrvB)
	for _, r := range rawResults {
		barCli := makeNetBar(float64(r.ClientToSrvB), maxRawB, 40)
		barSrv := makeNetBar(float64(r.SrvToClientB), maxRawB, 40)
		flagCli := "OK (1 paquete)"
		if r.ClientToSrvB > ethernetMSS {
			flagCli = "EXCEDE MSS -> FRAGMENTA (2 paquetes TCP)"
		}
		flagSrv := "OK (1 paquete)"
		if r.SrvToClientB > ethernetMSS {
			flagSrv = "EXCEDE MSS -> FRAGMENTA (2 paquetes TCP)"
		}
		fmt.Printf(" %-22s | Ida (pk)     [%s] %4d B -> %s\n", r.Name, barCli, r.ClientToSrvB, flagCli)
		fmt.Printf(" %-22s | Vuelta (c)   [%s] %4d B -> %s\n\n", "", barSrv, r.SrvToClientB, flagSrv)
	}

	// ==================== IMPRESION SECCION 2: PROTOCOLO TLS 1.3 ====================
	fmt.Println(line)
	fmt.Println(" 2. ANALISIS DE TRAFICO EN PROTOCOLO TLS 1.3 REAL (X25519 vs Hibrido X25519MLKEM768)")
	fmt.Println(line)
	fmt.Println(" Glosario de metricas TLS 1.3 interceptadas en el socket:")
	fmt.Println("  - ClientHello (1er Write) : Tamaño exacto del primer registro TLS enviado por el cliente (extensiones + key_share).")
	fmt.Println("  - Vuelo Servidor (Read)   : ServerHello + ChangeCipherSpec + EncryptedExtensions + Certificado X.509 + Verify + Finished.")
	fmt.Println("  - Total Handshake TLS     : Suma total de bytes de control TLS transmitidos por cliente y servidor antes del HTTP/AppData.")
	fmt.Println(subline)

	w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w2, "Configuracion TLS 1.3\tGroup ID\tClientHello\tVuelo Servidor\tTotal Handshake\tSegs TCP (CliHello / Srv)\tLatencia Socket")
	fmt.Fprintln(w2, "---------------------\t--------\t-----------\t--------------\t---------------\t-------------------------\t---------------")

	for _, r := range tlsResults {
		fmt.Fprintf(w2, "%s\t0x%04x\t%5d Bytes\t%6d Bytes\t%6d Bytes\t%d seg / %d seg\t%8.1f us\n",
			r.Name, uint16(r.CurveID), r.ClientHelloB, r.ServerTotalB, r.TotalHandshakeB, r.ClientHelloSegs, r.ServerFlightSeg, r.AvgLatencyUs)
	}
	w2.Flush()

	fmt.Println("\n" + subline)
	fmt.Println(" GRAFICO 2: DESGLOSE DEL HANDSHAKE TLS 1.3 EN EL CABLE (Bytes reales transmitidos en el socket)")
	fmt.Println(subline)

	maxTLS := float64(tlsHybrid.TotalHandshakeB)
	for _, r := range tlsResults {
		barCH := makeNetBar(float64(r.ClientHelloB), maxTLS, 42)
		barSrv := makeNetBar(float64(r.ServerTotalB), maxTLS, 42)
		barTot := makeNetBar(float64(r.TotalHandshakeB), maxTLS, 42)

		fmt.Printf(" %s:\n", r.Name)
		fmt.Printf("   ├─ ClientHello (Ida)       [%s] %4d Bytes (%d segmento/s TCP de %d B)\n", barCH, r.ClientHelloB, r.ClientHelloSegs, ethernetMSS)
		fmt.Printf("   ├─ ServerHello+Cert (Vta)  [%s] %4d Bytes (%d segmento/s TCP de %d B)\n", barSrv, r.ServerTotalB, r.ServerFlightSeg, ethernetMSS)
		fmt.Printf("   └─ Total Handshake TLS     [%s] %4d Bytes (%.2fx respecto a TLS Clasico)\n\n",
			barTot, r.TotalHandshakeB, float64(r.TotalHandshakeB)/float64(tlsClassic.TotalHandshakeB))
	}
	fmt.Println(line + "\n")
}