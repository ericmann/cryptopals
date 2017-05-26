package set2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
)

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "cryptopals: %s\n", err)
		os.Exit(1)
	}
}

func pad(bytes []byte, length int) []byte {
	pad := length - len(bytes)

	for len(bytes) < length {
		bytes = append(bytes, byte(pad))
	}

	return bytes
}

func xorBytes(chars, key []byte) []byte {
	j := 0
	keySize := len(key)
	result := []byte{}
	for i := range chars {
		result = append(result, chars[i]^key[j])
		j++

		// Loop back around if the key is smaller than the chars to XOR
		if j == keySize {
			j = 0
		}
	}
	return result
}

func cbcEncrypt(iv []byte, key []byte, plaintext []byte) ([]byte, error) {
	if len(iv) < aes.BlockSize {
		return nil, errors.New("Invalid IV")
	}

	block, err := aes.NewCipher(key)
	check(err)

	toPad := 16 - (len(plaintext) % aes.BlockSize)
	toEnc := pad(plaintext, len(plaintext)+toPad)

	encrypted := make([]byte, len(toEnc))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, toEnc)

	return encrypted, nil
}

func cbcDecrypt(iv []byte, key []byte, ciphertext []byte) ([]byte, error) {
	if len(iv) < aes.BlockSize {
		return nil, errors.New("Invalid IV")
	}

	block, err := aes.NewCipher(key)
	check(err)

	//plaintext := make([]byte, aes.BlockSize+len(toEnc))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}

func encryptionOracle(plaintext []byte) []byte {
	// Create a random 16-byte key
	key := make([]byte, 16)
	rand.Read(key)

	// Append and prepend 5-10 random bytes before and after
	before := make([]byte, 5+rand.Intn(5))
	rand.Read(before)
	after := make([]byte, 5+rand.Intn(5))
	rand.Read(after)
	plaintext = append(before, plaintext...)
	plaintext = append(plaintext, after...)

	toPad := 16 - (len(plaintext) % aes.BlockSize)
	plaintext = pad(plaintext, len(plaintext)+toPad)

	// Set up aes
	block, err := aes.NewCipher(key)
	check(err)

	// Choose the cipher
	choice := rand.Intn(10)
	if choice%2 == 0 {
		ciphertext := make([]byte, aes.BlockSize+len(plaintext))
		iv := ciphertext[:aes.BlockSize]
		rand.Read(iv) // Use a random IV
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

		return ciphertext
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	return ciphertext
}

func detectEcb(cipher []byte) bool {
	size := len(cipher)

	blocks := map[string]bool{}
	for i := 0; i < size; i += 16 {
		block := string(cipher[i : i+16])
		_, exists := blocks[block]

		// If we find a duplicate ciphertext, we've found a duplicate plaintext
		if exists {
			return true
		}

		// If no duplicate, save for later testing
		blocks[block] = true
	}

	return false
}

/*************************/
/*         Tasks         */
/*************************/

// Pad a string to an arbitrary length of bytes
func task1(str string, length int) []byte {
	bytes := []byte(str)

	return pad(bytes, length)
}

// Implement CBC mode
func task2(filePath string, fileKey string, fileIv []byte) []byte {
	iv := []byte{1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4}
	key := []byte{1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4}
	plain := []byte("This is a secret")
	fmt.Println(string(plain))

	cipher, _ := cbcEncrypt(iv, key, plain)
	fmt.Println(string(cipher))

	decrypt, _ := cbcDecrypt(iv, key, cipher)
	fmt.Println(string(decrypt))

	// Get bytes
	bytes, err := ioutil.ReadFile(filePath)
	check(err)

	encrypted, err := base64.StdEncoding.DecodeString(string(bytes))
	check(err)

	fileDecrypt, _ := cbcDecrypt(fileIv, []byte(fileKey), encrypted)

	return fileDecrypt
}

// ECB/CBC detection oracle
func task3() string {
	ecbCount := 0

	for i := 0; i < 1000; i++ {
		// Generate repeating-string plaintext
		plain := make([]byte, 240)
		for j := range plain {
			plain[j] = byte('B')
		}

		// Encrypt it
		cipher := encryptionOracle(plain)

		// Detect ECB
		if detectEcb(cipher) {
			ecbCount++
		}
	}

	return strconv.Itoa(ecbCount) + " / 1000"
}

// Go runs all sets in the challenge
func Go() {
	// Challenge 1
	fmt.Println("1: ", task1("YELLOW SUBMARINE", 20))

	// Challenge 2
	println("2: ", string(task2("data/10.txt", "YELLOW SUBMARINE", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})))
	//println("2: ", task2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))

	// Challenge 3
	println("3: ECB vs CBC detections => ", task3())
	//println("3: ", task3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

	// Challenge 4
	//println("4: ", task4("data/4.txt"))

	// Challenge 5
	//println("5: ", task5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))

	// Challenge 6
	//println("6: ", task6("data/6.txt", 2, 40))

	// Challenge 7
	//println("7: ", task7("data/7.txt", "YELLOW SUBMARINE"))

	// Challenge 8
	//println("8: ", task8("data/8.txt"))
}
