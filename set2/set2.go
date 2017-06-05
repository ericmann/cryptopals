package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"strconv"
)

func bin2hex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

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

func simpleCbcEncrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	toPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	plaintext = pad(plaintext, len(plaintext)+toPad)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv) // Use a random IV

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func ecbEncrypt(key []byte, plaintext []byte) []byte {
	toPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	plaintext = pad(plaintext, len(plaintext)+toPad)

	// Set up aes
	block, err := aes.NewCipher(key)
	check(err)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	return ciphertext
}

func ecbOracle(key []byte, plaintext []byte) []byte {
	toAppend := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	str, _ := base64.StdEncoding.DecodeString(toAppend)

	plaintext = append(plaintext, str...)

	toPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	plaintext = pad(plaintext, len(plaintext)+toPad)

	// Set up aes
	block, err := aes.NewCipher(key)
	check(err)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	return ciphertext
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

	// Choose the cipher
	choice := rand.Intn(10)
	if choice%2 == 0 {
		return simpleCbcEncrypt(key, plaintext)
	}

	return ecbEncrypt(key, plaintext)
}

func makeA(size int) []byte {
	output := make([]byte, size)
	for i := range output {
		output[i] = byte('A')
	}

	return output
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

func profileFor(email string) string {
	v := url.Values{}

	v.Set("email", email)
	// v.Set("uid", strconv.Itoa(10))
	// v.Set("role", "user")
	// Go natively orders query params alphabetically, we need role to be last!

	return v.Encode() + "&uid=10&role=user"
}

func encProfile(email string, key []byte) []byte {
	profile := profileFor(email)

	return ecbEncrypt(key, []byte(profile))
}

func decProfile(encrypted []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)

	out := make([]byte, len(encrypted))

	for i := 0; i < len(out); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], encrypted[i:i+aes.BlockSize])
	}

	// Remove padding
	last := int(out[len(out)-1])
	if last < block.BlockSize() {
		canStrip := true
		for i := len(out) - last; i < len(out); i++ {
			if out[i] != byte(last) {
				canStrip = false
				break
			}
		}
		if canStrip {
			out = out[:len(out)-last]
		}
	}

	return out
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

// Byte-at-a-time ECB decryption
func task4() {
	// Create a random 16-byte key
	key := make([]byte, 16)
	rand.Read(key)

	// Figure out how many blocks are added by the unknown string
	blocksAdded := len(ecbOracle(key, make([]byte, 0))) / aes.BlockSize

	// Build up a holder variable for the decoded text
	text := make([]byte, aes.BlockSize*blocksAdded)

	// Iterate over blocks
	for block := 0; block < blocksAdded; block++ {

		// Iterate over characters in the block
		for i := 0; i < aes.BlockSize; i++ {
			// Capture first block when we prefix with AAAAs of blockSize - 1
			prefix := makeA(aes.BlockSize - 1 - i)
			short := ecbOracle(key, prefix)
			short = short[aes.BlockSize*block : aes.BlockSize*(block+1)]

			// Find the array that matches the one-byte short block
			dummy := makeA(aes.BlockSize)
			if i > 0 && block == 0 {
				start := aes.BlockSize - 1 - i
				end := aes.BlockSize - 1
				tStart := aes.BlockSize * block
				tEnd := i + aes.BlockSize*block
				copy(dummy[start:end], text[tStart:tEnd])
			}
			if block > 0 {
				start := 0
				end := aes.BlockSize - 1
				tStart := aes.BlockSize*(block-1) + i + 1
				tEnd := aes.BlockSize*block + i
				copy(dummy[start:end], text[tStart:tEnd])
			}

			// Iterate over the last byte in the block
			for b := 0; b < 256; b++ {
				dummy[aes.BlockSize-1] = byte(b)
				out := ecbOracle(key, dummy)
				if bytes.Equal(out[:aes.BlockSize], short) {
					text[aes.BlockSize*block+i] = byte(b)
					break
				}
			}
		}
	}

	fmt.Println(string(text))
}

// Copy-and paste ECB
func task5(email string, role string) {
	key := make([]byte, 16)
	rand.Read(key)

	// Create a nefarious user
	bogus := "aa@m.comadmin           "
	bogusEnc := encProfile(bogus, key)

	// Capture the second block ("admin" + padding) only
	admin := bogusEnc[16:32]
	fmt.Println(string(decProfile(admin, key)))

	// Padd the specified email so the role is in a block of its own
	toPad := 32 - (2 + len("email=") + len(email) + len("&uid=10&role="))
	for i := 0; i < toPad; i++ {
		email += " "
	}

	// Encrypt the _real_ profile
	enc := encProfile(email, key)

	// Show the real profile
	dec := decProfile(enc, key)
	fmt.Println(url.ParseQuery(string(dec)))

	// Create a _bogus_ admin profile
	junk := append(enc[:32], admin...)

	// Show the broken profile
	junkDec := decProfile(junk, key)
	fmt.Println(url.ParseQuery(string(junkDec)))
}

// Go runs all sets in the challenge
func Go() {
	// Challenge 1
	fmt.Println("1: ", task1("YELLOW SUBMARINE", 20))

	// Challenge 2
	println("2: ", string(task2("data/10.txt", "YELLOW SUBMARINE", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})))

	// Challenge 3
	println("3: ECB vs CBC detections => ", task3())

	// Challenge 4
	println("4:")
	task4()

	// Challenge 5
	fmt.Println(profileFor("foo@bar.com"))
	task5("foo@bar.com", "admin")

	// Challenge 6
	//println("6: ", task6("data/6.txt", 2, 40))

	// Challenge 7
	//println("7: ", task7("data/7.txt", "YELLOW SUBMARINE"))

	// Challenge 8
	//println("8: ", task8("data/8.txt"))
}
