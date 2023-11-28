package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/sethvargo/go-password/password"
	"golang.org/x/crypto/pbkdf2"
)

type Crypter struct {}

func NewCrypter() *Crypter {
  return &Crypter{} 
}

func (c *Crypter) EncryptEncode(data []byte, passphrase string) ([]byte, error) {
	ciphertext, err := c.Encrypt(data, passphrase)
	if err != nil {
		return nil, err
	}
	var cipherEncode = make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(cipherEncode, ciphertext)

	return cipherEncode, nil
}
 
func (c *Crypter) DecodeDecrypt(encData []byte, passphrase string) ([]byte, error) {

	var decodedciphertext = make([]byte, hex.DecodedLen(len(encData)))
	_, err := hex.Decode(decodedciphertext, encData)
	if err != nil {
		return nil, err
	}

	return c.Decrypt(decodedciphertext, passphrase)
}

func (c *Crypter) Encrypt(data []byte, passphrase string) ([]byte, error) {
  
	key, salt := c.deriveKey(passphrase, nil, 0, 0, 0)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(salt, ciphertext...)

  return ciphertext, nil
}


// Takes in ciphertext without encoding with a passphrase and returns basic data in bytes 
// 
// Where the salt should be of length 16 bytes and we use golang.org/x/crypto/pbkdf2 package to derive a key from our passphrase.
// 
// Where derive a key of len 32 bytes to in turn use a AES-256 encryption. 
func (c *Crypter) Decrypt(data []byte, passphrase string) ([]byte, error) {
  
	salt := data[:16]
	data = data[16:]			
	key, _ := c.deriveKey(passphrase, salt, 0, 0, 0)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm , err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plainbytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

  return plainbytes, nil
}


// Here Even if this function is not public,
//
// if we don't have our own salt, and want to generate random salt, we leave the salt to nil
//
// And for saltsize, iterations and keyLen, if we want to use default values, we call those parameters with 0.
//
// The default values for Saltsize is 16 which gives 128 bit salt you could also give 8 as a value for 64 bit salt.
//
// Default iterations is 4096 which is the recommended value, but I don't know any other value so use other value at risk
//
// And if left 0, the default keyLen will be used as 32 which in turn used AES-256 in the encrypt function.
//
// But passphrase cannot be left nil of "" for obvious reasons
//
// And here you get the key and the salt as return
func (c *Crypter) deriveKey(passphrase string, salt []byte, saltsize int, iterations int, keyLen int) ([]byte, []byte) {
	if salt == nil {
		if saltsize != 0 {
			salt = c.deriveSalt(saltsize)
		} else {
			salt = c.deriveSalt(16)
		}
	}

	if iterations == 0 {
		iterations = 4096          // Recommended value
	}

	if keyLen == 0 {
		keyLen = 32                // Length for AES-256 keys
	}

	if passphrase == "" {
		panic(`Passphrase cannot be nil or " " `)
	}

	return pbkdf2.Key([]byte(passphrase), salt, iterations, keyLen, sha256.New), salt
}

// in length use 8 as len for 64 bit salt length and 16 for 128 bit salt length
func (c *Crypter) deriveSalt(len int) []byte {
	salt := make([]byte, len)
	rand.Read(salt)

	return salt
}


// Generated a Password of total length 20, number of digits and symbols 4 and 5 respectively. With Uppercase allowed and Repeat not allowed.
// 
// Here we have allowed symbols 	~!@#$%^&*()_|[]<>?,./ 
// 
// And to generate the password we are using the package github.com/sethvargo/go-password/password where the used functions being, NewGenerator and *Generator.Generate.
// You can check it out for more details. 
func (c *Crypter) GeneratePassword() (string, error) {
	gen, err := password.NewGenerator(&password.GeneratorInput{
		Symbols: "~!@#$%^&*()_|[]<>?,./",
	})
	if err != nil {
		return "", err
	}

	pass, err := gen.Generate(20, 4, 5, false, false)
	if err != nil {
		return "", err
	}
	
	return pass, nil
}