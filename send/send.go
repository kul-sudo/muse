package send

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"muse/constants"
	"muse/user"
	"net/http"
	"os"
	"path/filepath"
)

func Send(w http.ResponseWriter, r *http.Request, pgp *pgpCrypto.PGPHandle) {
	query := r.URL.Query()
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	recipientHash := sha256.New()
	recipientHash.Write([]byte(query.Get("recipient")))
	recipient := hex.EncodeToString(recipientHash.Sum(nil))

	recipientUser := user.User{}
	recipientData, err := os.ReadFile(filepath.Join(cwd, "users", recipient+".json"))
	if err != nil {
		fmt.Fprintf(w, "Maybe the recipient doesn't exist?")
		return
	}
	json.Unmarshal(recipientData, &recipientUser)

	recipientPrivateKey, err := pgpCrypto.NewKeyFromArmored(recipientUser.PrivateKey)
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	recipientPublicKey, err := recipientPrivateKey.ToPublic()
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	encryptionHandle, err := pgp.Encryption().Recipient(recipientPublicKey).New()
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	message := query.Get("message")
	pgpMessage, err := encryptionHandle.Encrypt([]byte(message))
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	armored, err := pgpMessage.Armor()
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	encryptionHandle.ClearPrivateParams()
	recipientUser.Messages = append(recipientUser.Messages, armored)

	recipientFile, err := os.Create(filepath.Join(cwd, "users", recipient+".json"))
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	recipientMarshal, err := json.Marshal(recipientUser)
	if err != nil {
		fmt.Fprintf(w, constants.SEND_ERROR)
		return
	}

	recipientFile.WriteString(string(recipientMarshal))
}
