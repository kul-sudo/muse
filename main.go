package main

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/opencoff/go-srp"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

type Username = string

const SRP_BITS int = 1024
const LOGIN_ERROR string = "Error logging in."

func register(w http.ResponseWriter, r *http.Request, users *map[Username][]string, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()

	var username Username = query.Get("username")
	password := query.Get("password")

	userPrivateKey, _ := pgp.KeyGeneration().
		AddUserId("username", "").
		New().GenerateKeyWithSecurity(constants.HighSecurity)

	bytePassword := []byte(password)

	hash, _ := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	pgp.LockKey(userPrivateKey, hash)

	(*users)[username] = make([]string, 0)

	byteUsername := []byte(username)

	s, err := srp.NewWithHash(crypto.SHA256, SRP_BITS)
	if err != nil {
		panic(err)
	}

	v, err := s.Verifier(byteUsername, bytePassword)
	if err != nil {
		panic(err)
	}

	ih, vh := v.Encode()

	os.MkdirAll(filepath.Join("users", ih), os.ModePerm)
	cwd, _ := os.Getwd()
	privateKeyFile, _ := os.Create(filepath.Join(cwd, "users", ih, "private.asc"))
	defer privateKeyFile.Close()
	armorPrivateKey, _ := userPrivateKey.Armor()
	privateKeyFile.WriteString(armorPrivateKey)

	verifierFile, _ := os.Create(filepath.Join(cwd, "users", ih, "verifier"))
	defer verifierFile.Close()
	verifierFile.WriteString(vh)

	fmt.Fprintf(w, "Success.")
}

func login(w http.ResponseWriter, r *http.Request, users *map[Username][]string) {
	query := r.URL.Query()

	var username Username = query.Get("username")
	password := query.Get("password")

	bytePassword := []byte(password)
	byteUsername := []byte(username)

	s, _ := srp.NewWithHash(crypto.SHA256, SRP_BITS)

	v, _ := s.Verifier(byteUsername, bytePassword)

	ih, _ := v.Encode()

	cwd, _ := os.Getwd()
	dat, err := os.ReadFile(filepath.Join(cwd, "users", ih, "verifier"))
	if err != nil {
		fmt.Fprintf(w, "Maybe you haven't registered?")
		return
	}

	vh := string(dat)
	c, err := s.NewClient(byteUsername, bytePassword)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// client credentials (public key and identity) to send to server
	creds := c.Credentials()

	// Begin the server by parsing the client public key and identity.
	ih, A, err := srp.ServerBegin(creds)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Now, pretend to lookup the user db using "I" as the key and
	// fetch salt, verifier etc.
	s, v, err = srp.MakeSRPVerifier(vh)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	srv, err := s.NewServer(v, A)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Generate the credentials to send to client
	creds = srv.Credentials()

	// client processes the server creds and generates
	// a mutual authenticator; the authenticator is sent
	// to the server as proof that the client derived its keys.
	cauth, err := c.Generate(creds)
	if err != nil {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Receive the proof of authentication from client
	proof, ok := srv.ClientOk(cauth)
	if !ok {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	// Verify the server's proof
	if !c.ServerOk(proof) {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	kc := c.RawKey()
	ks := srv.RawKey()

	if 1 != subtle.ConstantTimeCompare(kc, ks) {
		fmt.Fprintf(w, LOGIN_ERROR)
		return
	}

	fmt.Fprintf(w, "Logged in.")
}

func main() {
	pgp := pgpCrypto.PGPWithProfile(profile.RFC9580())

	users := make(map[Username][]string)

	http.HandleFunc("/register", func(writer http.ResponseWriter, request *http.Request) { register(writer, request, &users, pgp) })
	http.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) { login(writer, request, &users) })
	log.Fatal(http.ListenAndServe(":8080", nil))
}
