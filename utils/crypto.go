package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/base64"
	"os"
)

// VULNERABILITY: Hardcoded encryption key
var encryptionKey = []byte(os.Getenv("APP_ENCRYPTION_KEY"))

// VULNERABILITY: Hardcoded IV (Initialization Vector)
var iv = []byte("1234567890123456")

// VULNERABILITY: Using DES (weak, deprecated algorithm)
func EncryptDES(plaintext []byte) ([]byte, error) {
	// DES is considered insecure - key too short
	key := []byte("12345678") // 8 bytes for DES
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

// VULNERABILITY: Using RC4 (broken stream cipher)
func EncryptRC4(plaintext []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// VULNERABILITY: AES with static IV (nonce reuse)
func EncryptAESInsecure(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	// Using static IV is insecure - should be random for each encryption
	stream := cipher.NewCTR(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// VULNERABILITY: Weak encoding used as "encryption"
func ObfuscateData(data string) string {
	// Base64 is not encryption - provides no security
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// VULNERABILITY: ECB mode (patterns visible in ciphertext)
func EncryptAESECB(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	// ECB mode is insecure - identical plaintext blocks produce identical ciphertext
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	return ciphertext, nil
}
