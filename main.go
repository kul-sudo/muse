package main

import (
	pgpCrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"log"
	"muse/login"
	"muse/register"
	"muse/send"
	"net/http"
)

func main() {
	pgp := pgpCrypto.PGPWithProfile(profile.RFC9580())

	http.HandleFunc("/register", func(writer http.ResponseWriter, request *http.Request) { register.Register(writer, request, pgp) })
	http.HandleFunc("/send", func(writer http.ResponseWriter, request *http.Request) { send.Send(writer, request, pgp) })
	http.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) { login.Login(writer, request, pgp) })
	log.Fatal(http.ListenAndServe(":8080", nil))
}
