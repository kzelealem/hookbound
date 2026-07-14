package hookbound

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"strings"
)

const messageIDPrefix = "msg_"

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// IDGenerator creates stable, opaque webhook message identifiers.
type IDGenerator interface {
	NewMessageID() (string, error)
}

// RandomIDGenerator creates 128-bit cryptographically random identifiers.
type RandomIDGenerator struct {
	Reader io.Reader
}

func (g RandomIDGenerator) NewMessageID() (string, error) {
	reader := g.Reader
	if reader == nil {
		reader = rand.Reader
	}

	var entropy [16]byte
	if _, err := io.ReadFull(reader, entropy[:]); err != nil {
		return "", errors.Join(ErrIDGeneration, err)
	}
	return messageIDPrefix + strings.ToLower(idEncoding.EncodeToString(entropy[:])), nil
}

func idGeneratorOrRandom(generator IDGenerator) IDGenerator {
	if generator == nil {
		return RandomIDGenerator{}
	}
	return generator
}

// ValidateMessageID rejects values that could make the Standard Webhooks
// signature input ambiguous.
func ValidateMessageID(id string) error {
	if id == "" {
		return NewError(CodeInvalidMessage, "message id is required", nil)
	}
	if len(id) > 200 {
		return NewError(CodeInvalidMessage, "message id is too long", nil)
	}
	if strings.TrimSpace(id) != id || strings.ContainsRune(id, '.') {
		return NewError(CodeInvalidMessage, "message id contains forbidden characters", nil)
	}
	for index := 0; index < len(id); index++ {
		if id[index] < 0x20 || id[index] == 0x7f {
			return NewError(CodeInvalidMessage, "message id contains forbidden characters", nil)
		}
	}
	return nil
}
