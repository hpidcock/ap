package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/hpidcock/ap/internal/paths"
	"github.com/hpidcock/ap/internal/securestore"
)

// SaveVault writes the encrypted vault (0600).
func SaveVault(store *Store) error {
	data, err := json.Marshal(map[string]any{"credentials": store.All()})
	if err != nil {
		return err
	}
	return securestore.WriteFile(paths.VaultFile(), data)
}

// LoadVault reads the vault; a missing vault is empty, an undecryptable one is discarded.
func LoadVault() (*Store, error) {
	data, err := securestore.ReadFile(paths.VaultFile())
	if errors.Is(err, os.ErrNotExist) {
		return NewStore(nil), nil
	}
	if errors.Is(err, securestore.ErrCannotDecrypt) {
		// Keep the file: the keyring may just be unavailable right now. `ap logout` clears it.
		fmt.Fprintf(os.Stderr, "warning: cannot decrypt the vault with the current master key; serving an empty vault\n")
		return NewStore(nil), nil
	}
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Credentials []Credential `json:"credentials"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("corrupt vault: %w", err)
	}
	return NewStore(wrapper.Credentials), nil
}
