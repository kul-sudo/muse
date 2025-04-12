package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ProtonMail/bcrypt"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/opencoff/go-srp"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

const SRP_BITS int = 2048
const REGISTER_ERROR string = "Error registering."
const INCORRECT_PASSWORD_ERROR string = "Incorrect password."
const LOGIN_ERROR string = "Error logging in."
const SEND_ERROR string = "Send error."
const BCRYPT_MAX_COST_PART float32 = 0.5

type User struct {
	PrivateKey string   `json:"privateKey"`
	Verifier   string   `json:"verifier"`
	Messages   []string `json:"messages"`
	Salt       string   `json:"salt"`
}

func register(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()

	username := query.Get("username")
	password := query.Get("password")

	// Handle requirements for credentials
	if len(username) == 0 {
		fmt.Fprintf(w, "The username can't be empty.")
		return
	}

	if len(password) == 0 || len(password) >= 72 {
		fmt.Fprintf(w, "The password length has to be within the range 0..=72.")
		return
	}

	// Key generation
	userPrivateKey, err := pgp.KeyGeneration().
		AddUserId("username", "").
		New().GenerateKeyWithSecurity(constants.HighSecurity)
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	// Bcrypt hash generation
	salt, err := bcrypt.Salt()
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	hash, err := bcrypt.Hash(password, salt)
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	lockedKey, err := pgp.LockKey(userPrivateKey, []byte(hash))
	userPrivateKey = lockedKey

	// SRP
	srpEnv, err := srp.NewWithHash(crypto.SHA256, SRP_BITS)
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	verifier, err := srpEnv.Verifier([]byte(username), []byte(password))
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	identity, verifierString := verifier.Encode()

	// Add to the database
	os.Mkdir("users", os.ModePerm)
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	userFile, err := os.Create(filepath.Join(cwd, "users", identity+".json"))
	armorPrivateKey, err := userPrivateKey.Armor()
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	user := User{armorPrivateKey, verifierString, make([]string, 0), salt}
	userMarshal, err := json.Marshal(user)
	if err != nil {
		fmt.Fprintf(w, REGISTER_ERROR)
		return
	}

	userFile.WriteString(string(userMarshal))

	fmt.Fprintf(w, "Success.")
}

func login(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()

	// Login
	username := query.Get("username")
	password := query.Get("password")

	// Working with the credentials the user thinks are correct
	srpEnv, err := srp.NewWithHash(crypto.SHA256, SRP_BITS)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	client, err := srpEnv.NewClient([]byte(username), []byte(password))
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	credsClient := client.Credentials()

	identity, A, err := srp.ServerBegin(credsClient)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Fetch user from the database
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	user := User{}
	data, err := os.ReadFile(filepath.Join(cwd, "users", identity+".json"))
	if err != nil {
		fmt.Fprintf(w, "Maybe you haven't registered?")
	}
	json.Unmarshal(data, &user)

	// Working with the data stored in the database
	srpEnvStored, verifierStored, err := srp.MakeSRPVerifier(user.Verifier)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	srv, err := srpEnvStored.NewServer(verifierStored, A)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	credsServer := srv.Credentials()

	cauth, err := client.Generate(credsServer)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Verification
	proof, ok := srv.ClientOk(cauth)
	if !ok {
		fmt.Fprintf(w, INCORRECT_PASSWORD_ERROR)
		return
	}

	if !client.ServerOk(proof) {
		fmt.Fprintf(w, INCORRECT_PASSWORD_ERROR)
		return
	}

	kc := client.RawKey()
	ks := srv.RawKey()

	if subtle.ConstantTimeCompare(kc, ks) == 0 {
		fmt.Fprintf(w, INCORRECT_PASSWORD_ERROR)
		return
	}

	// Print out the messages
	hash, err := bcrypt.Hash(password, user.Salt)
	privateKey, err := pgpCrypto.NewPrivateKeyFromArmored(user.PrivateKey, []byte(hash))
	if err != nil {
		fmt.Fprintln(w, "Error unlocking the key.")
		return
	}
	decryptionHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	if err != nil {
		fmt.Fprintln(w, "DecryptionHandle error.")
		return
	}

	for i := 0; i < len(user.Messages); i++ {
		messageElement := user.Messages[i]
		// Decrypt data with a password
		decrypted, err := decryptionHandle.Decrypt([]byte(messageElement), pgpCrypto.Armor)
		if err != nil {
			fmt.Fprintln(w, "Decryption error.")
			return
		}

		myMessage := decrypted.Bytes()
		fmt.Fprintln(w, "anon: "+string(myMessage))
	}

	decryptionHandle.ClearPrivateParams()
}

func send(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	recipientHash := sha256.New()
	recipientHash.Write([]byte(query.Get("recipient")))
	recipient := hex.EncodeToString(recipientHash.Sum(nil))

	recipientUser := User{}
	recipientData, err := os.ReadFile(filepath.Join(cwd, "users", recipient+".json"))
	if err != nil {
		fmt.Fprintf(w, "Maybe the recipient doesn't exist?")
		return
	}
	json.Unmarshal(recipientData, &recipientUser)

	recipientPrivateKey, err := pgpCrypto.NewKeyFromArmored(recipientUser.PrivateKey)
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	recipientPublicKey, err := recipientPrivateKey.ToPublic()
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	encryptionHandle, err := pgp.Encryption().Recipient(recipientPublicKey).New()
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	message := query.Get("message")
	pgpMessage, err := encryptionHandle.Encrypt([]byte(message))
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	armored, err := pgpMessage.Armor()
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	encryptionHandle.ClearPrivateParams()
	recipientUser.Messages = append(recipientUser.Messages, armored)

	recipientFile, err := os.Create(filepath.Join(cwd, "users", recipient+".json"))
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	recipientMarshal, err := json.Marshal(recipientUser)
	if err != nil {
		fmt.Fprintf(w, SEND_ERROR)
		return
	}

	recipientFile.WriteString(string(recipientMarshal))
}

func main() {
	pgp := pgpCrypto.PGPWithProfile(profile.RFC9580())

	http.HandleFunc("/register", func(writer http.ResponseWriter, request *http.Request) { register(writer, request, pgp) })
	http.HandleFunc("/send", func(writer http.ResponseWriter, request *http.Request) { send(writer, request, pgp) })
	http.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) { login(writer, request, pgp) })
	log.Fatal(http.ListenAndServe(":8080", nil))
}
