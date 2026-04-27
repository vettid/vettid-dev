package main

// ============================================================================
// Wallet Storage Types
// ============================================================================

// WalletRecord is stored in encrypted SQLite at "wallets/{wallet_id}"
type WalletRecord struct {
	WalletID         string `json:"wallet_id"`
	Label            string `json:"label"`
	CryptoKeyID      string `json:"crypto_key_id"`      // References CryptoKeyV2.ID in credential
	Address          string `json:"address"`              // bech32 P2WPKH address
	DerivationPath   string `json:"derivation_path"`      // e.g. "m/84'/0'/0'/0/0"
	AccountIndex     int    `json:"account_index"`        // BIP44 account index
	Network          string `json:"network"`              // "mainnet" or "testnet"
	CachedBalance    int64  `json:"cached_balance_sats"`  // Satoshis, cached from last query
	BalanceUpdatedAt int64  `json:"balance_updated_at"`   // Unix timestamp
	CreatedAt        int64  `json:"created_at"`
	IsArchived       bool   `json:"is_archived"`          // Soft delete
	IsPublic         bool   `json:"is_public"`            // If true, address published to profile

	// BIP39Mnemonic is the wallet's 12-word backup phrase. Each wallet
	// has its own self-contained BIP39 entropy (independent of the
	// user's vault master) so wallets can be backed up to Critical
	// Secrets and, eventually, transferred to another vault. The
	// mnemonic is encrypted at rest by the vault DEK like every other
	// field on this record. Empty for legacy wallets created before
	// the BIP39 migration.
	BIP39Mnemonic string `json:"bip39_mnemonic,omitempty"`

	// SeedBackedUpAt is the unix-second timestamp when the user last
	// opted this wallet's seed phrase into Critical Secrets. Zero
	// means "not currently backed up". The actual seed value lives in
	// the credential's CriticalSecrets list — this field is only a
	// flag the UI uses to show the backup state without re-fetching.
	SeedBackedUpAt int64 `json:"seed_backed_up_at,omitempty"`

	// SeedBackupSecretID points at the CredentialSecretEntry.ID in
	// the user's Critical Secrets so wallet.revoke-backup can find
	// and remove the right entry without name-matching guesses.
	// Cleared on revoke.
	SeedBackupSecretID string `json:"seed_backup_secret_id,omitempty"`
}

// ============================================================================
// Blockchain API Types (mempool.space compatible)
// ============================================================================

// UTXO represents an unspent transaction output from the blockchain API
type UTXO struct {
	TxID   string     `json:"txid"`
	Vout   int        `json:"vout"`
	Value  int64      `json:"value"` // satoshis
	Status UTXOStatus `json:"status"`
}

// UTXOStatus is the confirmation status of a UTXO
type UTXOStatus struct {
	Confirmed   bool  `json:"confirmed"`
	BlockHeight int64 `json:"block_height,omitempty"`
	BlockTime   int64 `json:"block_time,omitempty"`
}

// FeeEstimate holds fee rate estimates from mempool.space
type FeeEstimate struct {
	FastestFee  int `json:"fastest_fee"`   // sat/vB for next block
	HalfHourFee int `json:"half_hour_fee"` // sat/vB for ~30 min
	HourFee     int `json:"hour_fee"`      // sat/vB for ~1 hour
	EconomyFee  int `json:"economy_fee"`   // sat/vB for economy
	MinimumFee  int `json:"minimum_fee"`   // sat/vB minimum relay fee
}

// AddressInfo holds balance information for a Bitcoin address
type AddressInfo struct {
	Address    string         `json:"address"`
	ChainStats AddressStats  `json:"chain_stats"`
	MempoolStats AddressStats `json:"mempool_stats"`
}

// AddressStats holds transaction statistics for an address
type AddressStats struct {
	FundedTxoCount int   `json:"funded_txo_count"`
	FundedTxoSum   int64 `json:"funded_txo_sum"`
	SpentTxoCount  int   `json:"spent_txo_count"`
	SpentTxoSum    int64 `json:"spent_txo_sum"`
}

// TxHistoryEntry represents a transaction in the address history
type TxHistoryEntry struct {
	TxID        string `json:"txid"`
	Version     int    `json:"version"`
	Locktime    int    `json:"locktime"`
	Size        int    `json:"size"`
	Weight      int    `json:"weight"`
	Fee         int64  `json:"fee"`
	Status      TxStatus `json:"status"`
	Vin         []TxVin  `json:"vin"`
	Vout        []TxVout `json:"vout"`
}

// TxStatus is the confirmation status of a transaction
type TxStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height,omitempty"`
	BlockHash   string `json:"block_hash,omitempty"`
	BlockTime   int64  `json:"block_time,omitempty"`
}

// TxVin represents a transaction input in history
type TxVin struct {
	TxID    string `json:"txid"`
	Vout    int    `json:"vout"`
	Prevout *TxVout `json:"prevout,omitempty"`
}

// TxVout represents a transaction output in history
type TxVout struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAsm  string `json:"scriptpubkey_asm,omitempty"`
	ScriptPubKeyType string `json:"scriptpubkey_type,omitempty"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address,omitempty"`
	Value            int64  `json:"value"`
}

// ============================================================================
// Wallet Handler Request Types
// ============================================================================

// WalletDetailRequest is the payload for wallet.detail
type WalletDetailRequest struct {
	WalletID string `json:"wallet_id"`
}

// WalletDetailResponse is the response for wallet.detail
type WalletDetailResponse struct {
	WalletID           string `json:"wallet_id"`
	Label              string `json:"label"`
	Address            string `json:"address"`
	Network            string `json:"network"`
	CachedBalanceSats  int64  `json:"cached_balance_sats"`
	BalanceUpdatedAt   int64  `json:"balance_updated_at"`
	IsPublic           bool   `json:"is_public"`
	SeedBackedUpAt     int64  `json:"seed_backed_up_at,omitempty"`
	SeedBackupSecretID string `json:"seed_backup_secret_id,omitempty"`
}

// WalletCreateRequest is the payload for wallet.create
type WalletCreateRequest struct {
	Label   string `json:"label"`
	Network string `json:"network,omitempty"` // defaults to "mainnet"
}

// WalletCreateResponse is the response for wallet.create
type WalletCreateResponse struct {
	WalletID       string `json:"wallet_id"`
	Label          string `json:"label"`
	Address        string `json:"address"`
	DerivationPath string `json:"derivation_path"`
	Network        string `json:"network"`
}

// WalletListResponse is the response for wallet.list
type WalletListResponse struct {
	Wallets []WalletListItem `json:"wallets"`
}

// WalletListItem is a single wallet entry in the list response
type WalletListItem struct {
	WalletID         string `json:"wallet_id"`
	Label            string `json:"label"`
	Address          string `json:"address"`
	Network          string `json:"network"`
	CachedBalance    int64  `json:"cached_balance_sats"`
	BalanceUpdatedAt int64  `json:"balance_updated_at"`
	IsPublic         bool   `json:"is_public"`
	IsArchived       bool   `json:"is_archived"`
}

// WalletGetBalanceRequest is the payload for wallet.get-balance
type WalletGetBalanceRequest struct {
	WalletID string `json:"wallet_id"`
}

// WalletGetBalanceResponse is the response for wallet.get-balance
type WalletGetBalanceResponse struct {
	WalletID        string `json:"wallet_id"`
	ConfirmedSats   int64  `json:"confirmed_sats"`
	UnconfirmedSats int64  `json:"unconfirmed_sats"`
	TotalSats       int64  `json:"total_sats"`
}

// WalletGetFeesResponse is the response for wallet.get-fees
type WalletGetFeesResponse struct {
	FastestFee  int `json:"fastest_fee"`
	HalfHourFee int `json:"half_hour_fee"`
	HourFee     int `json:"hour_fee"`
	EconomyFee  int `json:"economy_fee"`
	MinimumFee  int `json:"minimum_fee"`
}

// WalletSendRequest is the payload for wallet.send
type WalletSendRequest struct {
	WalletID    string `json:"wallet_id"`
	ToAddress   string `json:"to_address"`
	AmountSats  int64  `json:"amount_sats"`
	FeeRate     int    `json:"fee_rate"` // sat/vB
}

// WalletSendResponse is the response for wallet.send
type WalletSendResponse struct {
	TxID     string `json:"txid"`
	RawHex   string `json:"raw_hex,omitempty"` // Only if broadcast fails
	FeeSats  int64  `json:"fee_sats"`
	EstVsize int    `json:"est_vsize"`
}

// WalletSendToConnectionRequest is the payload for wallet.send-to-connection
type WalletSendToConnectionRequest struct {
	WalletID     string `json:"wallet_id"`
	ConnectionID string `json:"connection_id"`
	AmountSats   int64  `json:"amount_sats"`
	FeeRate      int    `json:"fee_rate"` // sat/vB
}

// WalletRequestPaymentRequest is the payload for wallet.request-payment
type WalletRequestPaymentRequest struct {
	WalletID     string `json:"wallet_id"`
	ConnectionID string `json:"connection_id"`
	AmountSats   int64  `json:"amount_sats"`
	Memo         string `json:"memo,omitempty"`
}

// WalletGetAddressRequest is the payload for wallet.get-address
type WalletGetAddressRequest struct {
	WalletID string `json:"wallet_id"`
}

// WalletGetAddressResponse is the response for wallet.get-address
type WalletGetAddressResponse struct {
	WalletID string `json:"wallet_id"`
	Address  string `json:"address"`
	Network  string `json:"network"`
}

// WalletGetHistoryRequest is the payload for wallet.get-history
type WalletGetHistoryRequest struct {
	WalletID string `json:"wallet_id"`
	Limit    int    `json:"limit,omitempty"` // default 20
}

// WalletGetHistoryResponse is the response for wallet.get-history
type WalletGetHistoryResponse struct {
	WalletID     string           `json:"wallet_id"`
	Transactions []WalletTxEntry  `json:"transactions"`
}

// WalletTxEntry is a simplified transaction entry for display
type WalletTxEntry struct {
	TxID        string `json:"txid"`
	Direction   string `json:"direction"` // "sent" or "received"
	AmountSats  int64  `json:"amount_sats"`
	FeeSats     int64  `json:"fee_sats"`
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height,omitempty"`
	BlockTime   int64  `json:"block_time,omitempty"`
}

// WalletDeleteRequest is the payload for wallet.delete
type WalletDeleteRequest struct {
	WalletID string `json:"wallet_id"`
}

// WalletSetVisibilityRequest is the payload for wallet.set-visibility
type WalletSetVisibilityRequest struct {
	WalletID string `json:"wallet_id"`
	IsPublic bool   `json:"is_public"`
}

// ============================================================================
// Messaging Content Types for BTC payments
// ============================================================================

// BtcPaymentRequestContent is the content for a btc_payment_request message
type BtcPaymentRequestContent struct {
	AmountSats int64  `json:"amount_sats"`
	Address    string `json:"address"`
	Memo       string `json:"memo,omitempty"`
	WalletID   string `json:"wallet_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"` // RFC3339
}

// BtcPaymentReceiptContent is the content for a btc_payment_receipt message
type BtcPaymentReceiptContent struct {
	TxID              string `json:"txid"`
	AmountSats        int64  `json:"amount_sats"`
	FeeSats           int64  `json:"fee_sats"`
	PaymentRequestID  string `json:"payment_request_id,omitempty"` // References original request message
	// SenderGUID identifies the payer so the receiving vault can resolve
	// the local connection_id for its audit trail. Optional for backwards
	// compatibility with older clients — receivers fall back to feed-only.
	SenderGUID string `json:"sender_guid,omitempty"`
}

// BtcAddressContent is the content for a btc_address message
type BtcAddressContent struct {
	Address  string `json:"address"`
	Label    string `json:"label,omitempty"`
	Network  string `json:"network"`
}

// ============================================================================
// Blockchain API URL helpers
// ============================================================================

const (
	mempoolMainnetBase = "https://mempool.space/api"
	mempoolTestnetBase = "https://mempool.space/testnet/api"
)

// MempoolBaseURL returns the mempool.space API base URL for the given network
func MempoolBaseURL(network string) string {
	if network == NetworkTestnet {
		return mempoolTestnetBase
	}
	return mempoolMainnetBase
}
