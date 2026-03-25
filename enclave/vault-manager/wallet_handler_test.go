package main

import (
	"encoding/json"
	"testing"
)

func TestWalletStorageKey(t *testing.T) {
	key := walletStorageKey("abc-123")
	expected := "wallets/abc-123"
	if key != expected {
		t.Errorf("walletStorageKey mismatch: got %s, want %s", key, expected)
	}
}

func TestSortUTXOsDescending(t *testing.T) {
	utxos := []UTXO{
		{TxID: "a", Value: 100},
		{TxID: "b", Value: 500},
		{TxID: "c", Value: 200},
		{TxID: "d", Value: 1000},
	}

	sortUTXOsDescending(utxos)

	if utxos[0].Value != 1000 {
		t.Errorf("expected first UTXO value 1000, got %d", utxos[0].Value)
	}
	if utxos[1].Value != 500 {
		t.Errorf("expected second UTXO value 500, got %d", utxos[1].Value)
	}
	if utxos[2].Value != 200 {
		t.Errorf("expected third UTXO value 200, got %d", utxos[2].Value)
	}
	if utxos[3].Value != 100 {
		t.Errorf("expected fourth UTXO value 100, got %d", utxos[3].Value)
	}
}

func TestClassifyTransaction(t *testing.T) {
	h := &WalletHandler{}

	// Test received transaction
	tx := TxHistoryEntry{
		Vout: []TxVout{
			{ScriptPubKeyAddr: "bc1qouraddr", Value: 50000},
			{ScriptPubKeyAddr: "bc1qother", Value: 30000},
		},
		Vin: []TxVin{
			{Prevout: &TxVout{ScriptPubKeyAddr: "bc1qsender", Value: 80000}},
		},
	}

	direction, amount := h.classifyTransaction(tx, "bc1qouraddr")
	if direction != "received" {
		t.Errorf("expected direction 'received', got %s", direction)
	}
	if amount != 50000 {
		t.Errorf("expected amount 50000, got %d", amount)
	}

	// Test sent transaction
	txSent := TxHistoryEntry{
		Vout: []TxVout{
			{ScriptPubKeyAddr: "bc1qdest", Value: 40000},
			{ScriptPubKeyAddr: "bc1qouraddr", Value: 9000}, // change
		},
		Vin: []TxVin{
			{Prevout: &TxVout{ScriptPubKeyAddr: "bc1qouraddr", Value: 50000}},
		},
	}

	direction, amount = h.classifyTransaction(txSent, "bc1qouraddr")
	if direction != "sent" {
		t.Errorf("expected direction 'sent', got %s", direction)
	}
	// sent = 50000 - 9000 = 41000
	if amount != 41000 {
		t.Errorf("expected amount 41000, got %d", amount)
	}
}

func TestWalletRecordJSON(t *testing.T) {
	record := WalletRecord{
		WalletID:       "test-wallet-id",
		Label:          "My Bitcoin",
		Address:        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		DerivationPath: "m/84'/0'/0'/0/0",
		AccountIndex:   0,
		Network:        "mainnet",
		IsPublic:       true,
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded WalletRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.WalletID != record.WalletID {
		t.Errorf("WalletID mismatch: got %s, want %s", decoded.WalletID, record.WalletID)
	}
	if decoded.Address != record.Address {
		t.Errorf("Address mismatch: got %s, want %s", decoded.Address, record.Address)
	}
	if decoded.IsPublic != true {
		t.Error("IsPublic should be true")
	}
	if decoded.Network != "mainnet" {
		t.Errorf("Network mismatch: got %s, want mainnet", decoded.Network)
	}
}

func TestBtcPaymentRequestContentJSON(t *testing.T) {
	req := BtcPaymentRequestContent{
		AmountSats: 50000,
		Address:    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Memo:       "Dinner last night",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded BtcPaymentRequestContent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.AmountSats != 50000 {
		t.Errorf("AmountSats mismatch: got %d, want 50000", decoded.AmountSats)
	}
	if decoded.Memo != "Dinner last night" {
		t.Errorf("Memo mismatch: got %s", decoded.Memo)
	}
}

func TestBtcPaymentReceiptContentJSON(t *testing.T) {
	receipt := BtcPaymentReceiptContent{
		TxID:       "abc123def456",
		AmountSats: 50000,
		FeeSats:    1500,
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded BtcPaymentReceiptContent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.TxID != "abc123def456" {
		t.Errorf("TxID mismatch: got %s", decoded.TxID)
	}
	if decoded.FeeSats != 1500 {
		t.Errorf("FeeSats mismatch: got %d", decoded.FeeSats)
	}
}

func TestMempoolBaseURL(t *testing.T) {
	mainnet := MempoolBaseURL("mainnet")
	if mainnet != "https://mempool.space/api" {
		t.Errorf("mainnet URL mismatch: got %s", mainnet)
	}

	testnet := MempoolBaseURL("testnet")
	if testnet != "https://mempool.space/testnet/api" {
		t.Errorf("testnet URL mismatch: got %s", testnet)
	}
}

func TestFeeEstimateJSON(t *testing.T) {
	fees := FeeEstimate{
		FastestFee:  25,
		HalfHourFee: 15,
		HourFee:     10,
		EconomyFee:  5,
		MinimumFee:  1,
	}

	data, err := json.Marshal(fees)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded FeeEstimate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.FastestFee != 25 {
		t.Errorf("FastestFee mismatch: got %d", decoded.FastestFee)
	}
	if decoded.MinimumFee != 1 {
		t.Errorf("MinimumFee mismatch: got %d", decoded.MinimumFee)
	}
}
