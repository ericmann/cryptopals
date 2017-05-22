package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

type charPair struct {
	key   byte
	value []byte
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "cryptopals: %s\n", err)
		os.Exit(1)
	}
}

func hex2bin(str string) []byte {
	bytes, err := hex.DecodeString(str)
	check(err)

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

func singleByteKeys(chars []byte) []charPair {
	pairs := []charPair{}

	for i := 0; i <= 255; i++ {
		key := byte(i)
		val := xorBytes(chars, []byte{key})

		pairs = append(pairs, charPair{key, val})
	}

	return pairs
}

func englishGuess(pairs []charPair) charPair {
	best := 0
	frequency := []byte("zqjxkvbpgyfwmculdrhsnioate")
	result := charPair{}
	for _, p := range pairs {
		score := 0
		for _, i := range p.value {
			score += bytes.IndexByte(frequency, i)
		}
		if score > best {
			best = score
			result = p
		}
	}
	return result
}

func distance(a, b []byte) int {
	result := 0
	for _, c := range xorBytes(a, b) {
		for i := 0; i < 8; i++ {
			result += int(c & 1)
			c >>= 1
		}
	}
	return result
}

func guessKeySize(chars []byte, minSize int, maxSize int) int {
	best := 0
	result := 0
	checks := len(chars) / maxSize
	for keySize := minSize; keySize <= maxSize; keySize++ {
		dist := 0
		first := chars[:keySize]
		for i := 1; i < checks; i++ {
			next := chars[keySize*i : keySize*(i+1)]
			dist += distance(first, next)
		}
		dist /= keySize
		if best == 0 || dist < best {
			best = dist
			result = keySize
		}
	}
	return result
}

func transpose(chars []byte, size int) [][]byte {
	result := make([][]byte, size)
	i := 0
	for _, c := range chars {
		result[i] = append(result[i], c)
		i++
		if i == size {
			i = 0
		}
	}
	return result
}

/*************************/
/*         Tasks         */
/*************************/

// Convert hex to base64
func task1(str string) string {
	bytes := hex2bin(str)

	return base64.StdEncoding.EncodeToString(bytes)
}

// Fixed XOR
func task2(first string, second string) string {
	firstBytes := hex2bin(first)
	secondBytes := hex2bin(second)

	return hex.EncodeToString(xorBytes(firstBytes, secondBytes))
}

// Single-byte XOR cipher
func task3(str string) string {
	bytes := hex2bin(str)
	pairs := singleByteKeys(bytes)

	guess := englishGuess(pairs)

	return string(guess.key) + ": " + string(guess.value)
}

// Detext single-character XOR
func task4(filePath string) string {
	file, err := os.Open(filePath)
	check(err)
	defer file.Close()

	all := []charPair{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		bytes, _ := hex.DecodeString(scanner.Text())
		for _, pairs := range singleByteKeys(bytes) {
			all = append(all, pairs)
		}
	}

	p := englishGuess(all)
	return string(p.key) + ": " + string(p.value)
}

// Repeating-key XOR
func task5(plain string, key string) string {
	return hex.EncodeToString(xorBytes([]byte(plain), []byte(key)))
}

// Break repeating-key XOR
func task6(filePath string, minKeySite int, maxKeySize int) string {
	// Get bytes
	bytes, err := ioutil.ReadFile(filePath)
	check(err)

	chars, err := base64.StdEncoding.DecodeString(string(bytes))
	check(err)

	// Estimate keySize
	keySize := guessKeySize(chars, minKeySite, maxKeySize)

	key := []byte{}

	// Transpose blocks
	for _, block := range transpose(chars, keySize) {
		// Solve each block
		p := englishGuess(singleByteKeys(block))

		// Compose key
		key = append(key, p.key)
	}

	// Decrypt
	value := xorBytes(chars, key)
	return "Key: " + string(key) + "\n" + string(value)
}

// Decrypt AES
func task7(filePath string, key string) string {
	// Get bytes
	bytes, err := ioutil.ReadFile(filePath)
	check(err)

	encrypted, err := base64.StdEncoding.DecodeString(string(bytes))
	check(err)

	cipher, err := aes.NewCipher([]byte(key))
	check(err)

	keySize := len(key)
	encryptedSize := len(encrypted)
	text := make([]byte, len(encrypted))
	for i := 0; i < encryptedSize; i += keySize {
		cipher.Decrypt(text[i:i+keySize], encrypted[i:i+keySize])
	}
	return string(text)
}

// Detect AES
func task8(filePath string) string {
	file, err := os.Open(filePath)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		encrypted, _ := base64.StdEncoding.DecodeString(line)
		encryptedSize := len(encrypted)

		// Keep track of each 16-byte block in a given message
		blocks := map[string]bool{}
		for i := 0; i < encryptedSize; i += 16 {
			block := string(encrypted[i : i+16])
			_, exists := blocks[block]

			// If we find a duplicate ciphertext, we've found a duplicate plaintext
			if exists {
				return line
			}

			// If no duplicate, save for later testing
			blocks[block] = true
		}
	}

	return ""
}

func main() {
	// Challenge 1
	println("1: ", task1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	// Challenge 2
	println("2: ", task2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))

	// Challenge 3
	println("3: ", task3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

	// Challenge 4
	println("4: ", task4("data/4.txt"))

	// Challenge 5
	println("5: ", task5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))

	// Challenge 6
	println(distance([]byte("this is a test"), []byte("wokka wokka!!!")))
	println("6: ", task6("data/6.txt", 2, 40))

	// Challenge 7
	println("7: ", task7("data/7.txt", "YELLOW SUBMARINE"))

	// Challenge 8
	println("8: ", task8("data/8.txt"))
}
