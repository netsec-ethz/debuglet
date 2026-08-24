package sui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/block-vision/sui-go-sdk/signer"
	"go.uber.org/zap"
)

func getKeypair(raw string) (*signer.Signer, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)

	if err != nil {
		return nil, err
	}
	switch decoded[0] {
	case 0:
		return signer.NewSigner(decoded[1:]), nil
	default:
		return nil, nil
	}
}

func LoadKeypair(path string, address string, logger *zap.Logger) (*signer.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []string
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}

	for _, entry := range entries {
		sig, err := getKeypair(entry)
		if err != nil {
			logger.Debug(err.Error())
		} else if strings.EqualFold(address, sig.Address) {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("Unable to load keypair for address %s", address)
}
