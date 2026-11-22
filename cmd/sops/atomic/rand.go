package atomic

import (
	"crypto/rand"
	"encoding/hex"
)

// randomSuffix returns 8 hex characters of cryptographic randomness so
// staging file names are unguessable and two concurrent runs never collide.
func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a recoverable situation for a
		// security-oriented CLI; panic matches os.CreateTemp's posture.
		panic("atomic: cannot read cryptographic randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}
