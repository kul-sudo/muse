package login

import (
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/ProtonMail/bcrypt"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/opencoff/go-srp"
	"muse/constants"
	"muse/user"
	"net/http"
	"os"
	"path/filepath"
)

func Login(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()

	// Login
	username := query.Get("username")
	password := query.Get("password")

	// Working with the credentials the user thinks are correct
	srpEnv, err := srp.NewWithHash(crypto.SHA256, constants.SRP_BITS)
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	client, err := srpEnv.NewClient([]byte(username), []byte(password))
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	credsClient := client.Credentials()

	identity, A, err := srp.ServerBegin(credsClient)
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	// Fetch user from the database
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	user := user.User{}
	data, err := os.ReadFile(filepath.Join(cwd, "users", identity+".json"))
	if err != nil {
		fmt.Fprintf(w, "Maybe you haven't registered?")
	}
	json.Unmarshal(data, &user)

	// Working with the data stored in the database
	srpEnvStored, verifierStored, err := srp.MakeSRPVerifier(user.Verifier)
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	srv, err := srpEnvStored.NewServer(verifierStored, A)
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	credsServer := srv.Credentials()

	cauth, err := client.Generate(credsServer)
	if err != nil {
		fmt.Fprintf(w, constants.LOGIN_ERROR)
		return
	}

	// Verification
	proof, ok := srv.ClientOk(cauth)
	if !ok {
		fmt.Fprintf(w, constants.INCORRECT_PASSWORD_ERROR)
		return
	}

	if !client.ServerOk(proof) {
		fmt.Fprintf(w, constants.INCORRECT_PASSWORD_ERROR)
		return
	}

	kc := client.RawKey()
	ks := srv.RawKey()

	if subtle.ConstantTimeCompare(kc, ks) == 0 {
		fmt.Fprintf(w, constants.INCORRECT_PASSWORD_ERROR)
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
