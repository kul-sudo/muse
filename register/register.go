package register

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/ProtonMail/bcrypt"
	pgpConstants "github.com/ProtonMail/gopenpgp/v3/constants"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/opencoff/go-srp"
	"muse/constants"
	"muse/user"
	"net/http"
	"os"
	"path/filepath"
)

func Register(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
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
		New().GenerateKeyWithSecurity(pgpConstants.HighSecurity)
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	// Bcrypt hash generation
	salt, err := bcrypt.Salt()
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	hash, err := bcrypt.Hash(password, salt)
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	lockedKey, err := pgp.LockKey(userPrivateKey, []byte(hash))
	userPrivateKey = lockedKey

	// SRP
	srpEnv, err := srp.NewWithHash(crypto.SHA256, constants.SRP_BITS)
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	verifier, err := srpEnv.Verifier([]byte(username), []byte(password))
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	identity, verifierString := verifier.Encode()

	// Add to the database
	os.Mkdir("users", os.ModePerm)
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	userFile, err := os.Create(filepath.Join(cwd, "users", identity+".json"))
	armorPrivateKey, err := userPrivateKey.Armor()
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	user := user.User{armorPrivateKey, verifierString, make([]string, 0), salt}
	userMarshal, err := json.Marshal(user)
	if err != nil {
		fmt.Fprintf(w, constants.REGISTER_ERROR)
		return
	}

	userFile.WriteString(string(userMarshal))

	fmt.Fprintf(w, "Success.")
}
