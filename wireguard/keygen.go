package wireguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func genPrivKey() (string, error) {
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("wg genkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func derivePubKey(privKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewBufferString(privKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func genPSK() (string, error) {
	out, err := exec.Command("wg", "genpsk").Output()
	if err != nil {
		return "", fmt.Errorf("wg genpsk: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func GenerateKeys() (priv, pub, psk string, err error) {
	priv, err = genPrivKey()
	if err != nil {
		return
	}
	pub, err = derivePubKey(priv)
	if err != nil {
		return
	}
	psk, err = genPSK()
	return
}
