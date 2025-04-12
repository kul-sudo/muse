package user

type User struct {
	PrivateKey string   `json:"privateKey"`
	Verifier   string   `json:"verifier"`
	Messages   []string `json:"messages"`
	Salt       string   `json:"salt"`
}
