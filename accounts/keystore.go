package accounts

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"JumboChain/types"

	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

func keyFileName(keyAddr types.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

var mnemonic string

var seed []byte

func NewAccount() string {
	id, err := uuid.NewRandom()
	if err != nil {
		fmt.Println("error creating account", err)
	}
	// idToStore := fmt.Sprintf("%v", id)
	// time := time.Now().UnixNano()
	// t := strconv.Itoa(int(time))
	// fmt.Printf("%v,%T", t, t)
	// mnemonic := GenerateMemonic()
	// seed := GenerateSeed(mnemonic)
	// fmt.Printf("%v,%T", seed, seed)
	privateKey := GeneratePrivateKey()
	prikey := fmt.Sprintf("%v", privateKey)
	// fmt.Println("\n-----------------------------------------")
	// fmt.Printf("prikey: %T, %d\n", prikey, unsafe.Sizeof(prikey))
	// fmt.Println("-----------------------------------------")
	publicKey := privateKey.PublicKey()
	// fmt.Printf("%v,%T", publicKey, publicKey)
	address := publicKey.Address()
	// fmt.Println("-------------------------------")
	// fmt.Printf("%v,%T\n", address, address)

	salt := GenerateRandomSaltForKeystore()
	// fmt.Println("\n-----------------------------------------")
	// fmt.Printf("salt: %T, %d\n", salt, unsafe.Sizeof(salt))
	// fmt.Println("-----------------------------------------")

	// salt is generated randomly from a-z & A-Z
	// fmt.Printf("%v,%T \n", salt, salt)
	// fmt.Println("This is line number 49")

	// fmt.Println("\n-----------------------------------------")
	// fmt.Printf("v: %T, %d\n", salt, unsafe.Sizeof(v))
	// fmt.Println("-----------------------------------------")
	privateKeyToStore, err := Encrypt(prikey, salt) // encoded private key/cipher text to store in keystore file
	// fmt.Println("privateKeyToStore:", privateKeyToStore)
	// fmt.Println("This is line number 51")
	if err != nil {
		fmt.Println(err)
	}
	finalAddress := fmt.Sprintf("%v", address) // Address will be stored in Keystore file

	w := hex.EncodeToString([]byte(mnemonic))

	derivedKey := pbkdf2.Key([]byte(mnemonic), []byte(salt), 1, 32, sha1.New) // derived key
	hashDerviedKey := sha256.Sum256(derivedKey)
	// fmt.Printf("Hashed Derived Key :-> %x\n", hashDerviedKey) // hash of derived key

	stringhashDerviedKey := fmt.Sprintf("%x", hashDerviedKey)

	// fmt.Println("stringhashDerviedKey:", stringhashDerviedKey)

	passphrase := privateKeyToStore + stringhashDerviedKey
	// fmt.Println("passphrase: ", passphrase)

	// hashOfPassphrase := sha256.Sum256([]byte(passphrase)) // this value should be equal to mac from keystore
	// fmt.Println("hashOfPassphrase", hashOfPassphrase)
	// hashOfPassphraseToStore := string(hashOfPassphrase[:]) //mac from keystore

	// fmt.Println("hashOfPassphraseToStore", passphrase)

	dataToStore := []string{"{", "address: ", "dh", finalAddress, " crypto:{", "aes-128-ctr", ",", "ciphertext: ", privateKeyToStore, ",", "cipherparams :{", "vi: ", w, "}", "kdf: ", "scrypt", ",", "kdfparams :", "{", "dkleng :", "32", ",", "n:", "262144", " ,", "p :", "1", ",", "r :", "8", " ,", "salt: ", string(salt), "} ", "mac: ", passphrase, " }", "id: ", id.String(), ",", "version :", "1", "}"}
	path := filepath.Join("keystore", keyFileName(address))
	forKeystore, err := os.Create(path)
	if err != nil {
		fmt.Println(err)
	}
	defer forKeystore.Close()
	for _, data := range dataToStore {
		_, err2 := forKeystore.WriteString(data)
		if err2 != nil {
			fmt.Println(err2)
		}
	}
	return ("dh" + finalAddress)
}

func GetPrivateKeyFromKeystore(addr string) string {
	var enckey string
	add, err := ReadAllFiles(addr)
	if err != nil {
		fmt.Println("Address is not valid", err)
	}
	// fmt.Println("before opening keystore")
	f, err := os.Open("./keystore/" + add)
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println("before scanning keystore file")
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// fmt.Println("scanner ->", scanner)
	for scanner.Scan() {

		words := strings.Fields(scanner.Text())
		// fmt.Println("Words :", words)
		for i, word := range words {
			// fmt.Println("word", word)
			if word == "mac:" {
				// fmt.Println("mac :", enckey)
				// fmt.Println("mac found", i)
				if i < len(words)-1 {
					enckey = words[i+1]
					// fmt.Println("Next word:", enckey)
				}
			}
		}
	}
	// fmt.Println("mac  found:", enckey)
	return (enckey)
}

func CompareInputWithMac(addr string, userInput string) bool {
	add, err := ReadAllFiles(addr)
	if err != nil {
		fmt.Println("Address is not valid", err)
	}
	macFromKeystore := GetPrivateKeyFromKeystore(add)
	if addr == macFromKeystore {
		fmt.Println("Account unlocked :", macFromKeystore)
	}
	fmt.Println("unlocked :", macFromKeystore)
	return true
}

func ReadAllFiles(addr string) (string, error) {
	var fileName string
	files, err := os.ReadDir("keystore")
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range files {
		fileName = f.Name()
		if strings.Contains(fileName, addr) {
			// fmt.Println(fileName)
		}
	}
	return fileName, nil
}

func GenerateRandomSaltForKeystore() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 12)
	var c string
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
		c = hex.EncodeToString(b)
	}
	// fmt.Println("b", c)
	return string(c)
}

func Encrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	buf := make([]byte, 16)
	cfb := cipher.NewCFBEncrypter(block, buf) // need a byte value known as initialization vector having problem here need input*
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decrypt(text, MySecret string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	buf := make([]byte, 16)
	cfb := cipher.NewCFBDecrypter(block, buf) // need a byte value known as initialization vector having problem here need input*
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
