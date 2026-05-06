package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ripemd160"
)

// Domain constant for BTC seed derivation from vault master secret.
// Domain separation prevents master secret reuse across contexts.
const DomainBTCSeed = "vettid-btc-seed-v1"

// BIP32 constants
const (
	// HardenedKeyStart is the index at which hardened keys start in BIP32
	HardenedKeyStart = 0x80000000
)

// Bitcoin network identifiers
const (
	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
)

// Bech32 HRP (human-readable part) per network
var bech32HRP = map[string]string{
	NetworkMainnet: "bc",
	NetworkTestnet: "tb",
}

// secp256k1 curve order N
var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// ============================================================================
// BIP32 HD Key Derivation
// ============================================================================

// ExtendedKey represents a BIP32 extended key (private key + chain code)
type ExtendedKey struct {
	Key       []byte // 32-byte private key
	ChainCode []byte // 32-byte chain code
	Depth     byte
	Index     uint32
}

// Wipe zeroizes the private key + chain code material. Callers must
// invoke this once they've copied out the bytes they need; the BIP32
// key tree the *ExtendedKey was derived from already lives only in
// stack memory, but the heap-allocated Key/ChainCode slices stick
// around until GC unless we explicitly zero them. SECURITY (crypto-H3).
func (k *ExtendedKey) Wipe() {
	if k == nil {
		return
	}
	zeroBytes(k.Key)
	zeroBytes(k.ChainCode)
}

// DeriveBTCSeed derives a BTC-specific seed from the vault master secret
// using HKDF-SHA256 with domain separation.
func DeriveBTCSeed(masterSecret []byte) ([]byte, error) {
	if len(masterSecret) < 16 {
		return nil, fmt.Errorf("master secret too short: need at least 16 bytes")
	}
	hkdfReader := hkdf.New(sha256.New, masterSecret, []byte(DomainBTCSeed), []byte("bitcoin-hd-wallet"))
	seed := make([]byte, 64) // BIP32 recommends 128-512 bits
	if _, err := io.ReadFull(hkdfReader, seed); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return seed, nil
}

// NewMasterKey creates a BIP32 master key from a seed.
// BIP32: HMAC-SHA512(key="Bitcoin seed", data=seed)
func NewMasterKey(seed []byte) (*ExtendedKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, fmt.Errorf("seed must be 16-64 bytes, got %d", len(seed))
	}
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	result := mac.Sum(nil)

	key := result[:32]
	chainCode := result[32:]

	// Validate private key is valid for secp256k1 (non-zero and < N)
	keyInt := new(big.Int).SetBytes(key)
	if keyInt.Sign() == 0 || keyInt.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid master key: out of secp256k1 range")
	}

	return &ExtendedKey{
		Key:       key,
		ChainCode: chainCode,
		Depth:     0,
		Index:     0,
	}, nil
}

// DeriveChild derives a BIP32 child key at the given index.
// For hardened derivation, index must include HardenedKeyStart.
func (k *ExtendedKey) DeriveChild(index uint32) (*ExtendedKey, error) {
	mac := hmac.New(sha512.New, k.ChainCode)

	if index >= HardenedKeyStart {
		// Hardened: data = 0x00 || private_key || index
		mac.Write([]byte{0x00})
		mac.Write(k.Key)
	} else {
		// Normal: data = compressed_public_key || index
		pubKey := PublicKeyFromPrivate(k.Key)
		mac.Write(pubKey)
	}

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	mac.Write(indexBytes)

	result := mac.Sum(nil)
	il := result[:32]
	ir := result[32:]

	// child_key = (IL + parent_key) mod N
	ilInt := new(big.Int).SetBytes(il)
	keyInt := new(big.Int).SetBytes(k.Key)
	childKey := new(big.Int).Add(ilInt, keyInt)
	childKey.Mod(childKey, secp256k1N)

	if childKey.Sign() == 0 {
		return nil, fmt.Errorf("derived key is zero (astronomically unlikely, try next index)")
	}

	// Pad to 32 bytes
	childKeyBytes := make([]byte, 32)
	b := childKey.Bytes()
	copy(childKeyBytes[32-len(b):], b)

	return &ExtendedKey{
		Key:       childKeyBytes,
		ChainCode: ir,
		Depth:     k.Depth + 1,
		Index:     index,
	}, nil
}

// DeriveBIP84Key derives a BIP84 key for native SegWit (P2WPKH).
// Path: m/84'/0'/account'/0/0 (mainnet) or m/84'/1'/account'/0/0 (testnet)
func DeriveBIP84Key(seed []byte, accountIndex int, network string) (*ExtendedKey, error) {
	master, err := NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}
	defer zeroBytes(master.Key)

	// Purpose: 84' (BIP84 native SegWit)
	purpose, err := master.DeriveChild(84 + HardenedKeyStart)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose: %w", err)
	}
	defer zeroBytes(purpose.Key)

	// Coin type: 0' for mainnet, 1' for testnet
	coinType := uint32(0)
	if network == NetworkTestnet {
		coinType = 1
	}
	coin, err := purpose.DeriveChild(coinType + HardenedKeyStart)
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type: %w", err)
	}
	defer zeroBytes(coin.Key)

	// Account index (hardened)
	account, err := coin.DeriveChild(uint32(accountIndex) + HardenedKeyStart)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account: %w", err)
	}
	defer zeroBytes(account.Key)

	// External chain (0 = receive, 1 = change)
	chain, err := account.DeriveChild(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chain: %w", err)
	}
	defer zeroBytes(chain.Key)

	// Address index 0
	addr, err := chain.DeriveChild(0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address: %w", err)
	}

	return addr, nil
}

// ============================================================================
// secp256k1 Key Operations
// ============================================================================

// PublicKeyFromPrivate computes the compressed secp256k1 public key (33 bytes)
func PublicKeyFromPrivate(privKey []byte) []byte {
	pk := secp256k1.PrivKeyFromBytes(privKey)
	return pk.PubKey().SerializeCompressed()
}

// ============================================================================
// Bech32 Encoding (inline implementation, ~80 lines)
// ============================================================================

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []int {
	result := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, int(c>>5))
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, int(c&31))
	}
	return result
}

func bech32CreateChecksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return checksum
}

func bech32Encode(hrp string, data []int) string {
	combined := append(data, bech32CreateChecksum(hrp, data)...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range combined {
		sb.WriteByte(bech32Charset[d])
	}
	return sb.String()
}

func bech32Decode(bech string) (string, []int, error) {
	if len(bech) > 90 {
		return "", nil, fmt.Errorf("bech32 string too long")
	}
	pos := strings.LastIndex(bech, "1")
	if pos < 1 || pos+7 > len(bech) {
		return "", nil, fmt.Errorf("invalid bech32 separator position")
	}
	hrp := strings.ToLower(bech[:pos])
	dataStr := strings.ToLower(bech[pos+1:])

	data := make([]int, len(dataStr))
	for i, c := range dataStr {
		idx := strings.IndexByte(bech32Charset, byte(c))
		if idx == -1 {
			return "", nil, fmt.Errorf("invalid bech32 character: %c", c)
		}
		data[i] = idx
	}

	if bech32Polymod(append(bech32HRPExpand(hrp), data...)) != 1 {
		return "", nil, fmt.Errorf("invalid bech32 checksum")
	}
	return hrp, data[:len(data)-6], nil
}

// convertBits converts data between bit group sizes (e.g., 8-bit to 5-bit)
func convertBits(data []byte, fromBits, toBits int, pad bool) ([]int, error) {
	acc := 0
	bits := 0
	maxv := (1 << uint(toBits)) - 1
	result := make([]int, 0, len(data)*fromBits/toBits+1)

	for _, d := range data {
		acc = (acc << uint(fromBits)) | int(d)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, (acc>>uint(bits))&maxv)
		}
	}
	if pad {
		if bits > 0 {
			result = append(result, (acc<<uint(toBits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<uint(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return result, nil
}

// ============================================================================
// Address Generation
// ============================================================================

// hash160 computes RIPEMD-160(SHA-256(data)) — standard Bitcoin pubkey hash
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	return r.Sum(nil)
}

// doubleSHA256 computes SHA-256(SHA-256(data)) — standard Bitcoin hash
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// P2WPKHAddress generates a P2WPKH (native SegWit) bech32 address
// from a compressed public key (33 bytes).
func P2WPKHAddress(compressedPubKey []byte, network string) (string, error) {
	if len(compressedPubKey) != 33 {
		return "", fmt.Errorf("expected 33-byte compressed public key, got %d", len(compressedPubKey))
	}
	hrp, ok := bech32HRP[network]
	if !ok {
		return "", fmt.Errorf("unsupported network: %s", network)
	}

	pkHash := hash160(compressedPubKey)

	data5bit, err := convertBits(pkHash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("bit conversion failed: %w", err)
	}

	// Prepend witness version 0
	data := append([]int{0}, data5bit...)
	return bech32Encode(hrp, data), nil
}

// P2WPKHScriptPubKey creates the scriptPubKey for a P2WPKH output.
// Format: OP_0 (0x00) OP_PUSH20 (0x14) <20-byte pubkey hash>
func P2WPKHScriptPubKey(pubKeyHash []byte) []byte {
	script := make([]byte, 22)
	script[0] = 0x00 // OP_0 (witness version 0)
	script[1] = 0x14 // Push 20 bytes
	copy(script[2:], pubKeyHash)
	return script
}

// P2WPKHScriptPubKeyFromAddress decodes a bech32 address and returns the scriptPubKey
func P2WPKHScriptPubKeyFromAddress(address string) ([]byte, error) {
	_, data, err := bech32Decode(address)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}
	if len(data) < 1 {
		return nil, fmt.Errorf("empty witness program")
	}
	if data[0] != 0 {
		return nil, fmt.Errorf("unsupported witness version: %d", data[0])
	}

	// Convert 5-bit data back to 8-bit
	programBytes := make([]byte, len(data[1:]))
	for i, v := range data[1:] {
		programBytes[i] = byte(v)
	}
	program8bit, err := convertBits(programBytes, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("bit conversion failed: %w", err)
	}

	pkHash := make([]byte, len(program8bit))
	for i, v := range program8bit {
		pkHash[i] = byte(v)
	}

	if len(pkHash) != 20 {
		return nil, fmt.Errorf("invalid witness program length: %d (expected 20)", len(pkHash))
	}

	return P2WPKHScriptPubKey(pkHash), nil
}

// ============================================================================
// Bitcoin Transaction Types
// ============================================================================

// BtcTxInput represents a transaction input
type BtcTxInput struct {
	TxID     [32]byte // Previous transaction hash (internal byte order, reversed from display)
	Vout     uint32   // Previous output index
	Sequence uint32   // Sequence number (0xFFFFFFFD enables RBF)
	Value    int64    // Value of the UTXO being spent (needed for SegWit signing)
}

// BtcTxOutput represents a transaction output
type BtcTxOutput struct {
	Value        int64  // Amount in satoshis
	ScriptPubKey []byte // Output script
}

// BtcTransaction represents a Bitcoin transaction
type BtcTransaction struct {
	Version  int32
	Inputs   []BtcTxInput
	Outputs  []BtcTxOutput
	Locktime uint32
}

// ============================================================================
// Transaction Serialization
// ============================================================================

// writeVarInt encodes a variable-length integer (Bitcoin protocol format)
func writeVarInt(val uint64) []byte {
	switch {
	case val < 0xfd:
		return []byte{byte(val)}
	case val <= 0xffff:
		b := make([]byte, 3)
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(val))
		return b
	case val <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(val))
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], val)
		return b
	}
}

// SerializeNoWitness serializes the transaction without witness data.
// Used for computing the txid (double SHA-256 of this).
func (tx *BtcTransaction) SerializeNoWitness() []byte {
	var buf []byte

	// Version (4 bytes LE)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(tx.Version))
	buf = append(buf, v...)

	// Input count
	buf = append(buf, writeVarInt(uint64(len(tx.Inputs)))...)

	// Inputs
	for _, in := range tx.Inputs {
		buf = append(buf, in.TxID[:]...)
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, in.Vout)
		buf = append(buf, vout...)
		buf = append(buf, 0x00) // Empty scriptSig (SegWit)
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, in.Sequence)
		buf = append(buf, seq...)
	}

	// Output count
	buf = append(buf, writeVarInt(uint64(len(tx.Outputs)))...)

	// Outputs
	for _, out := range tx.Outputs {
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, uint64(out.Value))
		buf = append(buf, val...)
		buf = append(buf, writeVarInt(uint64(len(out.ScriptPubKey)))...)
		buf = append(buf, out.ScriptPubKey...)
	}

	// Locktime (4 bytes LE)
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.Locktime)
	buf = append(buf, lt...)

	return buf
}

// SerializeWitness serializes the full transaction with witness data.
// This is the format broadcast to the network.
func (tx *BtcTransaction) SerializeWitness(witnesses [][]byte) []byte {
	var buf []byte

	// Version
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(tx.Version))
	buf = append(buf, v...)

	// SegWit marker and flag
	buf = append(buf, 0x00, 0x01)

	// Input count
	buf = append(buf, writeVarInt(uint64(len(tx.Inputs)))...)

	// Inputs
	for _, in := range tx.Inputs {
		buf = append(buf, in.TxID[:]...)
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, in.Vout)
		buf = append(buf, vout...)
		buf = append(buf, 0x00) // Empty scriptSig
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, in.Sequence)
		buf = append(buf, seq...)
	}

	// Output count
	buf = append(buf, writeVarInt(uint64(len(tx.Outputs)))...)

	// Outputs
	for _, out := range tx.Outputs {
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, uint64(out.Value))
		buf = append(buf, val...)
		buf = append(buf, writeVarInt(uint64(len(out.ScriptPubKey)))...)
		buf = append(buf, out.ScriptPubKey...)
	}

	// Witness data for each input
	for i := range tx.Inputs {
		if i < len(witnesses) {
			buf = append(buf, witnesses[i]...)
		} else {
			buf = append(buf, 0x00) // Empty witness
		}
	}

	// Locktime
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.Locktime)
	buf = append(buf, lt...)

	return buf
}

// TxID computes the transaction ID (double SHA-256 of non-witness serialization,
// displayed in reverse byte order per Bitcoin convention).
func (tx *BtcTransaction) TxID() string {
	hash := doubleSHA256(tx.SerializeNoWitness())
	// Reverse for display
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = hash[31-i]
	}
	return hex.EncodeToString(reversed)
}

// ============================================================================
// BIP143 Sighash (SegWit Signature Hash)
// ============================================================================

// hashPrevouts computes double SHA-256 of all input outpoints
func (tx *BtcTransaction) hashPrevouts() []byte {
	var buf []byte
	for _, in := range tx.Inputs {
		buf = append(buf, in.TxID[:]...)
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, in.Vout)
		buf = append(buf, vout...)
	}
	return doubleSHA256(buf)
}

// hashSequence computes double SHA-256 of all input sequences
func (tx *BtcTransaction) hashSequence() []byte {
	var buf []byte
	for _, in := range tx.Inputs {
		seq := make([]byte, 4)
		binary.LittleEndian.PutUint32(seq, in.Sequence)
		buf = append(buf, seq...)
	}
	return doubleSHA256(buf)
}

// hashOutputs computes double SHA-256 of all serialized outputs
func (tx *BtcTransaction) hashOutputs() []byte {
	var buf []byte
	for _, out := range tx.Outputs {
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, uint64(out.Value))
		buf = append(buf, val...)
		buf = append(buf, writeVarInt(uint64(len(out.ScriptPubKey)))...)
		buf = append(buf, out.ScriptPubKey...)
	}
	return doubleSHA256(buf)
}

// SighashBIP143 computes the BIP143 sighash for a P2WPKH input.
// pubKeyHash is RIPEMD-160(SHA-256(compressed_pubkey)) for the input being signed.
func (tx *BtcTransaction) SighashBIP143(inputIndex int, pubKeyHash []byte) ([]byte, error) {
	if inputIndex < 0 || inputIndex >= len(tx.Inputs) {
		return nil, fmt.Errorf("input index %d out of range (0-%d)", inputIndex, len(tx.Inputs)-1)
	}

	input := tx.Inputs[inputIndex]

	// scriptCode for P2WPKH: OP_DUP OP_HASH160 <20-byte-pkh> OP_EQUALVERIFY OP_CHECKSIG
	scriptCode := make([]byte, 25)
	scriptCode[0] = 0x76 // OP_DUP
	scriptCode[1] = 0xa9 // OP_HASH160
	scriptCode[2] = 0x14 // Push 20 bytes
	copy(scriptCode[3:23], pubKeyHash)
	scriptCode[23] = 0x88 // OP_EQUALVERIFY
	scriptCode[24] = 0xac // OP_CHECKSIG

	var buf []byte

	// 1. nVersion
	ver := make([]byte, 4)
	binary.LittleEndian.PutUint32(ver, uint32(tx.Version))
	buf = append(buf, ver...)

	// 2. hashPrevouts (SIGHASH_ALL)
	buf = append(buf, tx.hashPrevouts()...)

	// 3. hashSequence (SIGHASH_ALL)
	buf = append(buf, tx.hashSequence()...)

	// 4. outpoint being spent
	buf = append(buf, input.TxID[:]...)
	vout := make([]byte, 4)
	binary.LittleEndian.PutUint32(vout, input.Vout)
	buf = append(buf, vout...)

	// 5. scriptCode
	buf = append(buf, writeVarInt(uint64(len(scriptCode)))...)
	buf = append(buf, scriptCode...)

	// 6. value of the output being spent (8 bytes LE)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, uint64(input.Value))
	buf = append(buf, val...)

	// 7. nSequence of the input being signed
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, input.Sequence)
	buf = append(buf, seq...)

	// 8. hashOutputs (SIGHASH_ALL)
	buf = append(buf, tx.hashOutputs()...)

	// 9. nLocktime
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.Locktime)
	buf = append(buf, lt...)

	// 10. nHashType (SIGHASH_ALL = 0x01)
	ht := make([]byte, 4)
	binary.LittleEndian.PutUint32(ht, 1)
	buf = append(buf, ht...)

	return doubleSHA256(buf), nil
}

// ============================================================================
// Transaction Signing
// ============================================================================

// SignP2WPKHInput signs a single P2WPKH transaction input and returns the witness data.
// Witness format: [2 items] [sig_len] [DER signature + SIGHASH_ALL] [33] [compressed pubkey]
// SECURITY: Private key bytes are used directly from CryptoKeyV2; caller must zeroize.
func SignP2WPKHInput(tx *BtcTransaction, inputIndex int, privKeyBytes []byte) ([]byte, error) {
	pubKey := PublicKeyFromPrivate(privKeyBytes)
	pubKeyHash := hash160(pubKey)

	sighash, err := tx.SighashBIP143(inputIndex, pubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("sighash computation failed: %w", err)
	}

	// ECDSA sign with secp256k1
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	sig := ecdsa.Sign(privKey, sighash)
	sigDER := sig.Serialize()

	// Append SIGHASH_ALL type byte
	sigWithType := append(sigDER, 0x01)

	// Build witness stack: [num_items] [sig_len] [sig] [pubkey_len] [pubkey]
	var witness []byte
	witness = append(witness, 0x02) // 2 witness items
	witness = append(witness, writeVarInt(uint64(len(sigWithType)))...)
	witness = append(witness, sigWithType...)
	witness = append(witness, writeVarInt(uint64(len(pubKey)))...)
	witness = append(witness, pubKey...)

	return witness, nil
}

// SignAllInputs signs all inputs of a P2WPKH transaction with the same private key.
// Returns the serialized witness transaction and the txid.
// SECURITY: Private key never leaves the enclave; only the signed raw hex exits.
func SignAllInputs(tx *BtcTransaction, privKeyBytes []byte) (rawTxHex string, txid string, err error) {
	witnesses := make([][]byte, len(tx.Inputs))

	for i := range tx.Inputs {
		w, werr := SignP2WPKHInput(tx, i, privKeyBytes)
		if werr != nil {
			return "", "", fmt.Errorf("failed to sign input %d: %w", i, werr)
		}
		witnesses[i] = w
	}

	rawTx := tx.SerializeWitness(witnesses)
	return hex.EncodeToString(rawTx), tx.TxID(), nil
}

// ============================================================================
// Utility Functions
// ============================================================================

// ParseTxID converts a hex txid string to internal byte order (reversed).
// Bitcoin displays txids in reverse byte order.
func ParseTxID(txidHex string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(txidHex)
	if err != nil {
		return result, fmt.Errorf("invalid txid hex: %w", err)
	}
	if len(decoded) != 32 {
		return result, fmt.Errorf("txid must be 32 bytes, got %d", len(decoded))
	}
	for i := 0; i < 32; i++ {
		result[i] = decoded[31-i]
	}
	return result, nil
}

// EstimateP2WPKHTxVsize estimates the virtual size (vsize) of a P2WPKH transaction.
// vsize = ceil(weight / 4), where weight = base_size * 3 + total_size
func EstimateP2WPKHTxVsize(numInputs, numOutputs int) int {
	// Non-witness bytes per input: 32 (txid) + 4 (vout) + 1 (scriptLen=0) + 4 (sequence) = 41
	// Non-witness bytes per output: 8 (value) + 1 (scriptLen) + 22 (P2WPKH script) = 31
	// Fixed non-witness: 4 (version) + 1 (inputCount) + 1 (outputCount) + 4 (locktime) = 10
	baseSize := 10 + numInputs*41 + numOutputs*31

	// Witness bytes per input: 1 (items) + 1 (sigLen) + ~72 (sig+sighash) + 1 (pkLen) + 33 (pubkey) = ~108
	// Plus 2 bytes for marker+flag
	witnessSize := 2 + numInputs*108

	weight := baseSize*3 + baseSize + witnessSize
	return (weight + 3) / 4
}

// GenerateWalletKeypair derives a BTC wallet keypair from the vault master secret.
// Returns private key, compressed public key, bech32 address, and derivation path.
// SECURITY: Caller must zeroize the returned private key when done.
func GenerateWalletKeypair(masterSecret []byte, accountIndex int, network string) (privKey, pubKey []byte, address, derivationPath string, err error) {
	seed, err := DeriveBTCSeed(masterSecret)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to derive BTC seed: %w", err)
	}
	defer zeroBytes(seed)

	extKey, err := DeriveBIP84Key(seed, accountIndex, network)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to derive BIP84 key: %w", err)
	}
	defer extKey.Wipe()

	compressedPubKey := PublicKeyFromPrivate(extKey.Key)

	addr, err := P2WPKHAddress(compressedPubKey, network)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to generate address: %w", err)
	}

	coinType := 0
	if network == NetworkTestnet {
		coinType = 1
	}
	path := fmt.Sprintf("m/84'/%d'/%d'/0/0", coinType, accountIndex)

	// Copy private key for caller (must be zeroized by caller).
	// extKey.Key is wiped by the deferred Wipe() above.
	privKeyCopy := make([]byte, 32)
	copy(privKeyCopy, extKey.Key)

	return privKeyCopy, compressedPubKey, addr, path, nil
}
