package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// BIP32 Test Vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func TestBIP32MasterKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Chain m public key (compressed)
	pubKey := PublicKeyFromPrivate(master.Key)
	expectedPub := "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
	if hex.EncodeToString(pubKey) != expectedPub {
		t.Errorf("master public key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(pubKey), expectedPub)
	}

	expectedChain := "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
	if hex.EncodeToString(master.ChainCode) != expectedChain {
		t.Errorf("master chain code mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(master.ChainCode), expectedChain)
	}
}

func TestBIP32HardenedChild(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Chain m/0' (hardened child)
	child, err := master.DeriveChild(0 + HardenedKeyStart)
	if err != nil {
		t.Fatalf("DeriveChild(0') failed: %v", err)
	}

	pubKey := PublicKeyFromPrivate(child.Key)
	expectedPub := "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
	if hex.EncodeToString(pubKey) != expectedPub {
		t.Errorf("m/0' public key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(pubKey), expectedPub)
	}

	expectedChain := "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
	if hex.EncodeToString(child.ChainCode) != expectedChain {
		t.Errorf("m/0' chain code mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(child.ChainCode), expectedChain)
	}
}

func TestBIP32DeepDerivation(t *testing.T) {
	// BIP32 Test Vector 1: m/0'/1/2'/2/1000000000
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// m/0'
	key, err := master.DeriveChild(0 + HardenedKeyStart)
	if err != nil {
		t.Fatalf("m/0' failed: %v", err)
	}

	// m/0'/1
	key, err = key.DeriveChild(1)
	if err != nil {
		t.Fatalf("m/0'/1 failed: %v", err)
	}

	pubKey := PublicKeyFromPrivate(key.Key)
	expectedPub := "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
	if hex.EncodeToString(pubKey) != expectedPub {
		t.Errorf("m/0'/1 public key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(pubKey), expectedPub)
	}

	// m/0'/1/2'
	key, err = key.DeriveChild(2 + HardenedKeyStart)
	if err != nil {
		t.Fatalf("m/0'/1/2' failed: %v", err)
	}

	pubKey = PublicKeyFromPrivate(key.Key)
	expectedPub = "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
	if hex.EncodeToString(pubKey) != expectedPub {
		t.Errorf("m/0'/1/2' public key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(pubKey), expectedPub)
	}

	// m/0'/1/2'/2
	key, err = key.DeriveChild(2)
	if err != nil {
		t.Fatalf("m/0'/1/2'/2 failed: %v", err)
	}

	// m/0'/1/2'/2/1000000000
	key, err = key.DeriveChild(1000000000)
	if err != nil {
		t.Fatalf("m/0'/1/2'/2/1000000000 failed: %v", err)
	}

	pubKey = PublicKeyFromPrivate(key.Key)
	expectedPub = "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
	if hex.EncodeToString(pubKey) != expectedPub {
		t.Errorf("m/0'/1/2'/2/1000000000 public key mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(pubKey), expectedPub)
	}
}

func TestBech32Encode(t *testing.T) {
	// Test vector from BIP173: P2WPKH address
	// pubkey hash: 751e76e8199196d454941c45d1b3a323f1433bd6
	pkHash, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6")

	data5bit, err := convertBits(pkHash, 8, 5, true)
	if err != nil {
		t.Fatalf("convertBits failed: %v", err)
	}
	data := append([]int{0}, data5bit...)

	address := bech32Encode("bc", data)
	expected := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if address != expected {
		t.Errorf("bech32 address mismatch:\n  got:  %s\n  want: %s", address, expected)
	}
}

func TestBech32RoundTrip(t *testing.T) {
	address := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

	hrp, data, err := bech32Decode(address)
	if err != nil {
		t.Fatalf("bech32Decode failed: %v", err)
	}

	if hrp != "bc" {
		t.Errorf("HRP mismatch: got %s, want bc", hrp)
	}
	if data[0] != 0 {
		t.Errorf("witness version mismatch: got %d, want 0", data[0])
	}

	// Re-encode and verify
	reencoded := bech32Encode(hrp, data)
	if reencoded != address {
		t.Errorf("roundtrip failed:\n  got:  %s\n  want: %s", reencoded, address)
	}
}

func TestP2WPKHAddress(t *testing.T) {
	// Test with a known compressed public key
	// This is the pubkey for the BIP173 test vector
	pubKey, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

	address, err := P2WPKHAddress(pubKey, NetworkMainnet)
	if err != nil {
		t.Fatalf("P2WPKHAddress failed: %v", err)
	}

	expected := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	if address != expected {
		t.Errorf("P2WPKH address mismatch:\n  got:  %s\n  want: %s", address, expected)
	}
}

func TestP2WPKHScriptPubKeyFromAddress(t *testing.T) {
	address := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

	script, err := P2WPKHScriptPubKeyFromAddress(address)
	if err != nil {
		t.Fatalf("P2WPKHScriptPubKeyFromAddress failed: %v", err)
	}

	// Expected: OP_0 OP_PUSH20 <pubkey_hash>
	expected := "0014751e76e8199196d454941c45d1b3a323f1433bd6"
	if hex.EncodeToString(script) != expected {
		t.Errorf("scriptPubKey mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(script), expected)
	}
}

func TestParseTxID(t *testing.T) {
	// Test that txid parsing reverses byte order correctly
	txidHex := "0000000000000000000000000000000000000000000000000000000000000001"
	result, err := ParseTxID(txidHex)
	if err != nil {
		t.Fatalf("ParseTxID failed: %v", err)
	}

	// Internal order should be reversed: display "00...01" becomes internal [01 00...00]
	if result[0] != 0x01 {
		t.Errorf("expected first byte to be 0x01 (reversed), got 0x%02x", result[0])
	}
	if result[31] != 0x00 {
		t.Errorf("expected last byte to be 0x00, got 0x%02x", result[31])
	}
}

func TestEstimateVsize(t *testing.T) {
	// A typical 1-input, 2-output P2WPKH transaction is ~141 vbytes
	vsize := EstimateP2WPKHTxVsize(1, 2)
	if vsize < 130 || vsize > 160 {
		t.Errorf("estimated vsize %d outside expected range 130-160 for 1-in-2-out", vsize)
	}

	// 2-input, 2-output should be ~209 vbytes
	vsize2 := EstimateP2WPKHTxVsize(2, 2)
	if vsize2 < 190 || vsize2 > 230 {
		t.Errorf("estimated vsize %d outside expected range 190-230 for 2-in-2-out", vsize2)
	}
}

func TestDeriveBTCSeed(t *testing.T) {
	// Test deterministic seed derivation
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	seed1, err := DeriveBTCSeed(masterSecret)
	if err != nil {
		t.Fatalf("DeriveBTCSeed failed: %v", err)
	}

	seed2, err := DeriveBTCSeed(masterSecret)
	if err != nil {
		t.Fatalf("DeriveBTCSeed (2) failed: %v", err)
	}

	if hex.EncodeToString(seed1) != hex.EncodeToString(seed2) {
		t.Error("DeriveBTCSeed is not deterministic")
	}

	if len(seed1) != 64 {
		t.Errorf("expected 64-byte seed, got %d", len(seed1))
	}
}

func TestGenerateWalletKeypair(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}

	privKey, pubKey, address, path, err := GenerateWalletKeypair(masterSecret, 0, NetworkMainnet)
	if err != nil {
		t.Fatalf("GenerateWalletKeypair failed: %v", err)
	}

	// Check key sizes
	if len(privKey) != 32 {
		t.Errorf("expected 32-byte private key, got %d", len(privKey))
	}
	if len(pubKey) != 33 {
		t.Errorf("expected 33-byte compressed public key, got %d", len(pubKey))
	}

	// Check address format
	if address[:3] != "bc1" {
		t.Errorf("expected mainnet address starting with bc1, got %s", address[:3])
	}

	// Check derivation path
	expectedPath := "m/84'/0'/0'/0/0"
	if path != expectedPath {
		t.Errorf("path mismatch: got %s, want %s", path, expectedPath)
	}

	// Verify deterministic: same input produces same output
	privKey2, _, address2, _, err := GenerateWalletKeypair(masterSecret, 0, NetworkMainnet)
	if err != nil {
		t.Fatalf("GenerateWalletKeypair (2) failed: %v", err)
	}
	if hex.EncodeToString(privKey) != hex.EncodeToString(privKey2) {
		t.Error("GenerateWalletKeypair is not deterministic")
	}
	if address != address2 {
		t.Error("address is not deterministic")
	}

	// Test different account index produces different key
	_, _, address3, path3, err := GenerateWalletKeypair(masterSecret, 1, NetworkMainnet)
	if err != nil {
		t.Fatalf("GenerateWalletKeypair (account 1) failed: %v", err)
	}
	if address3 == address {
		t.Error("different account index should produce different address")
	}
	expectedPath3 := "m/84'/0'/1'/0/0"
	if path3 != expectedPath3 {
		t.Errorf("path mismatch for account 1: got %s, want %s", path3, expectedPath3)
	}

	// Zeroize private keys
	zeroBytes(privKey)
	zeroBytes(privKey2)
}

func TestGenerateWalletKeypairTestnet(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}

	privKey, _, address, path, err := GenerateWalletKeypair(masterSecret, 0, NetworkTestnet)
	if err != nil {
		t.Fatalf("GenerateWalletKeypair testnet failed: %v", err)
	}
	defer zeroBytes(privKey)

	if address[:3] != "tb1" {
		t.Errorf("expected testnet address starting with tb1, got %s", address[:3])
	}

	expectedPath := "m/84'/1'/0'/0/0"
	if path != expectedPath {
		t.Errorf("testnet path mismatch: got %s, want %s", path, expectedPath)
	}
}

func TestWriteVarInt(t *testing.T) {
	tests := []struct {
		val      uint64
		expected string
	}{
		{0, "00"},
		{1, "01"},
		{0xfc, "fc"},
		{0xfd, "fdfd00"},
		{0xffff, "fdffff"},
		{0x10000, "fe00000100"},
	}
	for _, tt := range tests {
		result := writeVarInt(tt.val)
		if hex.EncodeToString(result) != tt.expected {
			t.Errorf("writeVarInt(%d) = %s, want %s", tt.val, hex.EncodeToString(result), tt.expected)
		}
	}
}

func TestHash160(t *testing.T) {
	// Test hash160 with a known value
	// SHA-256(0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
	// then RIPEMD-160 should give the pubkey hash from the BIP173 test
	pubKey, _ := hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	result := hash160(pubKey)
	expected := "751e76e8199196d454941c45d1b3a323f1433bd6"
	if hex.EncodeToString(result) != expected {
		t.Errorf("hash160 mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(result), expected)
	}
}

func TestTransactionSigning(t *testing.T) {
	// Create a simple test transaction and verify it can be signed
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}

	privKey, _, _, _, err := GenerateWalletKeypair(masterSecret, 0, NetworkTestnet)
	if err != nil {
		t.Fatalf("GenerateWalletKeypair failed: %v", err)
	}
	defer zeroBytes(privKey)

	// Create a dummy UTXO input
	txid, _ := ParseTxID("a" + strings.Repeat("0", 63))

	// Create a dummy output
	destScript, _ := hex.DecodeString("0014751e76e8199196d454941c45d1b3a323f1433bd6")

	tx := &BtcTransaction{
		Version: 2,
		Inputs: []BtcTxInput{
			{
				TxID:     txid,
				Vout:     0,
				Sequence: 0xFFFFFFFD,
				Value:    100000, // 0.001 BTC
			},
		},
		Outputs: []BtcTxOutput{
			{
				Value:        90000,
				ScriptPubKey: destScript,
			},
		},
		Locktime: 0,
	}

	rawHex, txidResult, err := SignAllInputs(tx, privKey)
	if err != nil {
		t.Fatalf("SignAllInputs failed: %v", err)
	}

	if len(rawHex) == 0 {
		t.Error("signed transaction is empty")
	}
	if len(txidResult) != 64 {
		t.Errorf("expected 64-char txid, got %d chars", len(txidResult))
	}

	// Verify the raw transaction can be decoded as hex
	_, err = hex.DecodeString(rawHex)
	if err != nil {
		t.Errorf("signed transaction is not valid hex: %v", err)
	}
}
