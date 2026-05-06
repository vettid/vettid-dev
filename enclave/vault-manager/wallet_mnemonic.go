package main

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// generateWalletMnemonic mints a fresh 12-word BIP39 mnemonic from
// 128 bits of cryptographically random entropy. Returned mnemonic is
// the canonical backup phrase for the wallet — exporting it is the
// only path the user has to recover or transfer this wallet.
//
// SECURITY (crypto-H3): returned as []byte so callers can wipe the
// memory after use; Go strings are immutable so a string return would
// stay on the heap until GC.
func generateWalletMnemonic() ([]byte, error) {
	entropy, err := bip39.NewEntropy(128) // 12 words
	if err != nil {
		return nil, fmt.Errorf("entropy: %w", err)
	}
	defer zeroBytes(entropy)
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("mnemonic: %w", err)
	}
	// The library returns a string; copy into a []byte the caller can
	// zero. The original string allocation will GC out shortly after.
	out := []byte(mnemonic)
	return out, nil
}

// mnemonicToSeed runs the standard BIP39 PBKDF2 derivation
// (PBKDF2-HMAC-SHA512, 2048 rounds) to turn a mnemonic into the
// 64-byte BIP32 master seed. Passphrase is empty in our flow — it
// would conflict with the in-vault Critical-Secrets gate.
func mnemonicToSeed(mnemonic []byte) ([]byte, error) {
	mnStr := string(mnemonic)
	if !bip39.IsMnemonicValid(mnStr) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	return bip39.NewSeed(mnStr, ""), nil
}

// generateWalletKeypairFromMnemonic is the BIP39-driven counterpart of
// GenerateWalletKeypair: each wallet has its OWN BIP39 root, so the
// BIP44 path always uses account=0 (no shared accounts/index across
// wallets). Returns the same shape as GenerateWalletKeypair so the
// rest of the wallet handler code is unchanged.
//
// SECURITY: caller must zeroize the returned private key when done.
func generateWalletKeypairFromMnemonic(mnemonic []byte, network string) (privKey, pubKey []byte, address, derivationPath string, err error) {
	seed, err := mnemonicToSeed(mnemonic)
	if err != nil {
		return nil, nil, "", "", err
	}
	defer zeroBytes(seed)

	// account=0 — each wallet has a fresh BIP39 root.
	extKey, err := DeriveBIP84Key(seed, 0, network)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("derive BIP84 key: %w", err)
	}
	defer extKey.Wipe()

	compressedPubKey := PublicKeyFromPrivate(extKey.Key)
	addr, err := P2WPKHAddress(compressedPubKey, network)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("address: %w", err)
	}

	coinType := 0
	if network == NetworkTestnet {
		coinType = 1
	}
	path := fmt.Sprintf("m/84'/%d'/0'/0/0", coinType)

	// extKey.Key is wiped by the deferred Wipe() above.
	privKeyCopy := make([]byte, 32)
	copy(privKeyCopy, extKey.Key)

	return privKeyCopy, compressedPubKey, addr, path, nil
}
