package kmscertsigner

import "crypto"

type realPrivateKey interface {
	Public() crypto.PublicKey
	Equal(crypto.PrivateKey) bool
}
