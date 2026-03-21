package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// LoadChain reads a JSON array of Attestation from the given file path.
// Returns an empty slice (not an error) if the file does not exist, so the
// first sign invocation in a pipeline creates the chain file automatically.
func LoadChain(path string) ([]types.Attestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []types.Attestation{}, nil
		}
		return nil, fmt.Errorf("reading chain file %s: %w", path, err)
	}
	var attestations []types.Attestation
	if err := json.Unmarshal(data, &attestations); err != nil {
		return nil, fmt.Errorf("parsing chain file %s: %w", path, err)
	}
	return attestations, nil
}

// SaveChain writes a JSON array of Attestation to the given file path,
// creating or truncating it. Uses indented JSON for human readability and
// audit trails.
func SaveChain(path string, attestations []types.Attestation) error {
	data, err := json.MarshalIndent(attestations, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling chain: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing chain file %s: %w", path, err)
	}
	return nil
}
