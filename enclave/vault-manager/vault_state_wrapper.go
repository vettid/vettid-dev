package main

import (
	"encoding/json"
	"fmt"
)

// vaultStateWrapper is the on-disk envelope for vault_state.enc, added
// in the D3 split-brain fix. The wrapper sits BETWEEN the
// vault-manager's createEncryptedVaultState output and the bytes that
// land in S3, so the encrypted payload itself is untouched but the
// supervisor sees an additional monotonic generation counter and a
// format version it can validate before unwrapping.
//
// Pre-D3 vault_state.enc objects are raw encrypted bytes with no JSON
// envelope. Detection on cold load is: try json.Unmarshal first; if
// that fails or the wrapper version is zero, treat the bytes as legacy
// payload and seed Generation=0. The next store re-writes them inside
// a v1 wrapper, so the legacy path drains naturally as users unlock.
type vaultStateWrapper struct {
	Version    int    `json:"v"`
	Generation int64  `json:"g"`
	Payload    []byte `json:"p"`
}

const vaultStateWrapperVersion = 1

// wrapVaultState produces the bytes that go to S3: a v1 wrapper around
// the encrypted payload with the supplied generation stamp. nextGen
// MUST be strictly greater than the loaded generation; callers
// compute it as `currentGen + 1` after verifying we still own the
// object.
func wrapVaultState(payload []byte, nextGen int64) ([]byte, error) {
	w := vaultStateWrapper{
		Version:    vaultStateWrapperVersion,
		Generation: nextGen,
		Payload:    payload,
	}
	return json.Marshal(&w)
}

// unwrapVaultState returns (payload, generation, isLegacy, err) for
// bytes loaded from S3. isLegacy=true means the bytes weren't a valid
// v1 wrapper — treat them as raw pre-D3 payload with generation 0; the
// next store will write them back inside a wrapper. err is reserved
// for the case where the wrapper parses but contains an unsupported
// version, which is a real format-drift signal we should fail loudly on.
func unwrapVaultState(blob []byte) (payload []byte, generation int64, isLegacy bool, err error) {
	if len(blob) == 0 {
		return nil, 0, true, nil
	}

	var w vaultStateWrapper
	if jsonErr := json.Unmarshal(blob, &w); jsonErr != nil {
		// Not JSON at all — pre-D3 raw encrypted bytes.
		return blob, 0, true, nil
	}
	if w.Version == 0 && len(w.Payload) == 0 {
		// Parsed as JSON but doesn't look like our wrapper at all
		// (e.g. unrelated object that landed at this key). Safer to
		// treat as legacy than to silently zero-out the payload.
		return blob, 0, true, nil
	}
	if w.Version != vaultStateWrapperVersion {
		return nil, 0, false, fmt.Errorf("unsupported vault_state wrapper version: %d", w.Version)
	}
	return w.Payload, w.Generation, false, nil
}
