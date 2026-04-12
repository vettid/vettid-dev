package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// WalletHandler handles Bitcoin wallet operations inside the enclave.
// Private keys never leave the enclave — only signed transaction hex exits.
type WalletHandler struct {
	ownerSpace   string
	storage      *EncryptedStorage
	vaultState   *VaultState
	eventHandler *EventHandler
	publisher    *VsockPublisher
	httpProxy    *HTTPProxy
}

// NewWalletHandler creates a new wallet handler
func NewWalletHandler(
	ownerSpace string,
	storage *EncryptedStorage,
	vaultState *VaultState,
	eventHandler *EventHandler,
	publisher *VsockPublisher,
	httpProxy *HTTPProxy,
) *WalletHandler {
	return &WalletHandler{
		ownerSpace:   ownerSpace,
		storage:      storage,
		vaultState:   vaultState,
		eventHandler: eventHandler,
		publisher:    publisher,
		httpProxy:    httpProxy,
	}
}

// Storage keys for wallet records
const walletIndexKey = "wallets/_index"

func walletStorageKey(walletID string) string {
	return "wallets/" + walletID
}

// ============================================================================
// Core Wallet Operations
// ============================================================================

// HandleCreate creates a new BTC wallet by deriving a keypair from the vault master secret
func (h *WalletHandler) HandleCreate(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletCreateRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	if req.Label == "" {
		return errorResponse(msg.GetID(), "label is required"), nil
	}

	network := req.Network
	if network == "" {
		network = NetworkMainnet
	}
	if network != NetworkMainnet && network != NetworkTestnet {
		return errorResponse(msg.GetID(), "invalid network: must be mainnet or testnet"), nil
	}

	// Check credential is available
	h.vaultState.mu.RLock()
	credential := h.vaultState.credential
	h.vaultState.mu.RUnlock()

	if credential == nil {
		return errorResponse(msg.GetID(), "vault not unlocked"), nil
	}

	if len(credential.VaultMasterSecret) == 0 {
		return errorResponse(msg.GetID(), "vault master secret not available"), nil
	}

	// Find next available account index
	accountIndex := h.nextAccountIndex()

	// Derive BIP84 keypair from master secret
	privKey, pubKey, address, derivPath, err := GenerateWalletKeypair(
		credential.VaultMasterSecret, accountIndex, network,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate wallet keypair")
		return errorResponse(msg.GetID(), "key derivation failed"), nil
	}

	walletID := uuid.New().String()
	cryptoKeyID := uuid.New().String()

	// Add CryptoKey to credential
	h.vaultState.mu.Lock()
	h.vaultState.credential.CryptoKeys = append(h.vaultState.credential.CryptoKeys, CryptoKey{
		Label:      req.Label,
		Type:       "secp256k1",
		PrivateKey: privKey,
		CreatedAt:  time.Now().Unix(),
	})
	h.vaultState.mu.Unlock()

	// Store wallet metadata in encrypted SQLite
	now := time.Now().Unix()
	record := WalletRecord{
		WalletID:       walletID,
		Label:          req.Label,
		CryptoKeyID:    cryptoKeyID,
		Address:        address,
		DerivationPath: derivPath,
		AccountIndex:   accountIndex,
		Network:        network,
		CreatedAt:      now,
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to serialize wallet record"), nil
	}

	if err := h.storage.Put(walletStorageKey(walletID), recordJSON); err != nil {
		log.Error().Err(err).Str("wallet_id", walletID).Msg("Failed to store wallet record")
		return errorResponse(msg.GetID(), "failed to store wallet"), nil
	}

	// Add to wallet index
	if err := h.storage.AddToIndex(walletIndexKey, walletID); err != nil {
		log.Error().Err(err).Msg("Failed to update wallet index")
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeWalletCreated,
			Metadata: map[string]string{
				"wallet_id": walletID,
				"address":   address,
				"network":   network,
				"label":     req.Label,
			},
		})
	}

	log.Info().
		Str("wallet_id", walletID).
		Str("address", address).
		Str("network", network).
		Str("path", derivPath).
		Msg("BTC wallet created")

	// Don't log pubkey/privkey details
	_ = pubKey

	resp := WalletCreateResponse{
		WalletID:       walletID,
		Label:          req.Label,
		Address:        address,
		DerivationPath: derivPath,
		Network:        network,
	}

	return successResponse(msg.GetID(), resp)
}

// HandleDetail returns details for a single wallet
func (h *WalletHandler) HandleDetail(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletDetailRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	return successResponse(msg.GetID(), WalletDetailResponse{
		WalletID:          record.WalletID,
		Label:             record.Label,
		Address:           record.Address,
		Network:           record.Network,
		CachedBalanceSats: record.CachedBalance,
		BalanceUpdatedAt:  record.BalanceUpdatedAt,
		IsPublic:          record.IsPublic,
	})
}

// HandleList returns all wallets for the user
func (h *WalletHandler) HandleList(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	wallets, err := h.loadAllWallets()
	if err != nil {
		log.Error().Err(err).Msg("Failed to load wallets")
		return errorResponse(msg.GetID(), "failed to load wallets"), nil
	}

	items := make([]WalletListItem, 0, len(wallets))
	for _, w := range wallets {
		items = append(items, WalletListItem{
			WalletID:         w.WalletID,
			Label:            w.Label,
			Address:          w.Address,
			Network:          w.Network,
			CachedBalance:    w.CachedBalance,
			BalanceUpdatedAt: w.BalanceUpdatedAt,
			IsPublic:         w.IsPublic,
			IsArchived:       w.IsArchived,
		})
	}

	return successResponse(msg.GetID(), WalletListResponse{Wallets: items})
}

// HandleGetAddress returns the receive address for a specific wallet
func (h *WalletHandler) HandleGetAddress(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletGetAddressRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	return successResponse(msg.GetID(), WalletGetAddressResponse{
		WalletID: record.WalletID,
		Address:  record.Address,
		Network:  record.Network,
	})
}

// HandleDelete soft-deletes a wallet (archives it; key stays in credential for recovery)
func (h *WalletHandler) HandleDelete(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletDeleteRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	record.IsArchived = true

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to serialize wallet"), nil
	}

	if err := h.storage.Put(walletStorageKey(req.WalletID), recordJSON); err != nil {
		return errorResponse(msg.GetID(), "failed to update wallet"), nil
	}

	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeWalletDeleted,
			Metadata: map[string]string{
				"wallet_id": req.WalletID,
			},
		})
	}

	return successResponse(msg.GetID(), map[string]bool{"success": true})
}

// HandleSetVisibility toggles the public/private visibility of a wallet address.
// When public, the address is published to the user's profile.
func (h *WalletHandler) HandleSetVisibility(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletSetVisibilityRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	record.IsPublic = req.IsPublic

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to serialize wallet"), nil
	}

	if err := h.storage.Put(walletStorageKey(req.WalletID), recordJSON); err != nil {
		return errorResponse(msg.GetID(), "failed to update wallet"), nil
	}

	log.Info().
		Str("wallet_id", req.WalletID).
		Bool("is_public", req.IsPublic).
		Msg("Wallet visibility changed")

	// Trigger profile re-publish so connections see the updated wallet addresses
	if h.publisher != nil {
		go h.republishProfile()
	}

	return successResponse(msg.GetID(), map[string]interface{}{
		"success":   true,
		"is_public": req.IsPublic,
	})
}

// republishProfile triggers a profile re-publish to update public wallet addresses.
// Uses the shared BuildPublishedProfile function for consistency.
func (h *WalletHandler) republishProfile() {
	profile := BuildPublishedProfile(h.ownerSpace, h.storage, h.vaultState)

	profileBytes, err := json.Marshal(profile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize profile for wallet visibility update")
		return
	}

	subject := fmt.Sprintf("OwnerSpace.%s.forApp.profile.public", h.ownerSpace)
	if err := h.publisher.PublishRaw(subject, profileBytes); err != nil {
		log.Error().Err(err).Msg("Failed to re-publish profile after wallet visibility change")
	} else {
		log.Info().
			Str("owner_space", h.ownerSpace).
			Int("wallet_count", len(profile.Wallets)).
			Msg("Profile re-published after wallet visibility change")
	}
}

// ============================================================================
// Blockchain Operations (require HTTP proxy)
// ============================================================================

// HandleGetBalance fetches the current balance for a wallet via mempool.space API
func (h *WalletHandler) HandleGetBalance(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletGetBalanceRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	if h.httpProxy == nil {
		return errorResponse(msg.GetID(), "HTTP proxy not available"), nil
	}

	// Fetch address info from mempool.space
	url := fmt.Sprintf("%s/address/%s", MempoolBaseURL(record.Network), record.Address)
	body, status, err := h.httpProxy.Get(url, nil)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch balance")
		return errorResponse(msg.GetID(), "failed to fetch balance: "+err.Error()), nil
	}
	if status != 200 {
		return errorResponse(msg.GetID(), fmt.Sprintf("blockchain API returned status %d", status)), nil
	}

	var info AddressInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return errorResponse(msg.GetID(), "failed to parse balance response"), nil
	}

	confirmedBalance := info.ChainStats.FundedTxoSum - info.ChainStats.SpentTxoSum
	unconfirmedBalance := info.MempoolStats.FundedTxoSum - info.MempoolStats.SpentTxoSum

	// Cache the balance
	record.CachedBalance = confirmedBalance + unconfirmedBalance
	record.BalanceUpdatedAt = time.Now().Unix()
	recordJSON, _ := json.Marshal(record)
	_ = h.storage.Put(walletStorageKey(req.WalletID), recordJSON)

	return successResponse(msg.GetID(), WalletGetBalanceResponse{
		WalletID:        req.WalletID,
		ConfirmedSats:   confirmedBalance,
		UnconfirmedSats: unconfirmedBalance,
		TotalSats:       confirmedBalance + unconfirmedBalance,
	})
}

// HandleGetFees fetches current fee estimates from mempool.space
func (h *WalletHandler) HandleGetFees(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	if h.httpProxy == nil {
		return errorResponse(msg.GetID(), "HTTP proxy not available"), nil
	}

	// Default to mainnet for fee estimation
	url := mempoolMainnetBase + "/v1/fees/recommended"
	body, status, err := h.httpProxy.Get(url, nil)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to fetch fees: "+err.Error()), nil
	}
	if status != 200 {
		return errorResponse(msg.GetID(), fmt.Sprintf("fee API returned status %d", status)), nil
	}

	var fees FeeEstimate
	if err := json.Unmarshal(body, &fees); err != nil {
		return errorResponse(msg.GetID(), "failed to parse fee response"), nil
	}

	return successResponse(msg.GetID(), WalletGetFeesResponse{
		FastestFee:  fees.FastestFee,
		HalfHourFee: fees.HalfHourFee,
		HourFee:     fees.HourFee,
		EconomyFee:  fees.EconomyFee,
		MinimumFee:  fees.MinimumFee,
	})
}

// HandleSend constructs, signs, and broadcasts a BTC transaction.
// The entire process happens inside the enclave — only the signed raw hex leaves.
func (h *WalletHandler) HandleSend(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletSendRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	if req.AmountSats <= 0 {
		return errorResponse(msg.GetID(), "amount must be positive"), nil
	}
	if req.FeeRate <= 0 {
		return errorResponse(msg.GetID(), "fee_rate must be positive"), nil
	}
	if req.ToAddress == "" {
		return errorResponse(msg.GetID(), "to_address is required"), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	if h.httpProxy == nil {
		return errorResponse(msg.GetID(), "HTTP proxy not available"), nil
	}

	// Validate destination address can be decoded to a scriptPubKey
	destScript, err := P2WPKHScriptPubKeyFromAddress(req.ToAddress)
	if err != nil {
		return errorResponse(msg.GetID(), "invalid destination address: "+err.Error()), nil
	}

	// Fetch UTXOs
	utxos, err := h.fetchUTXOs(record)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to fetch UTXOs: "+err.Error()), nil
	}

	if len(utxos) == 0 {
		return errorResponse(msg.GetID(), "no UTXOs available (zero balance)"), nil
	}

	// Find the private key for this wallet from the credential
	privKey, err := h.findPrivateKey(record)
	if err != nil {
		return errorResponse(msg.GetID(), "private key not found: "+err.Error()), nil
	}
	defer zeroBytes(privKey)

	// Build the sender's scriptPubKey for change output
	senderPubKey := PublicKeyFromPrivate(privKey)
	senderPKHash := hash160(senderPubKey)
	changeScript := P2WPKHScriptPubKey(senderPKHash)

	// Select UTXOs and build transaction
	tx, err := h.buildTransaction(utxos, destScript, changeScript, req.AmountSats, req.FeeRate, record)
	if err != nil {
		return errorResponse(msg.GetID(), err.Error()), nil
	}

	// Sign all inputs
	rawHex, txid, err := SignAllInputs(tx, privKey)
	if err != nil {
		return errorResponse(msg.GetID(), "signing failed: "+err.Error()), nil
	}

	// Broadcast
	broadcastURL := fmt.Sprintf("%s/tx", MempoolBaseURL(record.Network))
	_, status, err := h.httpProxy.Post(broadcastURL, []byte(rawHex), nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to broadcast transaction")
		// Return the raw hex so user can manually broadcast
		return successResponse(msg.GetID(), WalletSendResponse{
			TxID:    txid,
			RawHex:  rawHex,
			FeeSats: h.calculateFee(tx),
		})
	}
	if status != 200 {
		log.Warn().Int("status", status).Msg("Broadcast returned non-200 status")
		return successResponse(msg.GetID(), WalletSendResponse{
			TxID:    txid,
			RawHex:  rawHex,
			FeeSats: h.calculateFee(tx),
		})
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypeWalletTxBroadcast,
			Metadata: map[string]string{
				"wallet_id":  req.WalletID,
				"txid":       txid,
				"to_address": req.ToAddress,
				"amount":     fmt.Sprintf("%d", req.AmountSats),
			},
		})
	}

	log.Info().
		Str("txid", txid).
		Str("wallet_id", req.WalletID).
		Int64("amount_sats", req.AmountSats).
		Msg("BTC transaction broadcast")

	return successResponse(msg.GetID(), WalletSendResponse{
		TxID:     txid,
		FeeSats:  h.calculateFee(tx),
		EstVsize: EstimateP2WPKHTxVsize(len(tx.Inputs), len(tx.Outputs)),
	})
}

// HandleGetHistory fetches transaction history for a wallet
func (h *WalletHandler) HandleGetHistory(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletGetHistoryRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	if h.httpProxy == nil {
		return errorResponse(msg.GetID(), "HTTP proxy not available"), nil
	}

	url := fmt.Sprintf("%s/address/%s/txs", MempoolBaseURL(record.Network), record.Address)
	body, status, err := h.httpProxy.Get(url, nil)
	if err != nil {
		return errorResponse(msg.GetID(), "failed to fetch history: "+err.Error()), nil
	}
	if status != 200 {
		return errorResponse(msg.GetID(), fmt.Sprintf("history API returned status %d", status)), nil
	}

	var txHistory []TxHistoryEntry
	if err := json.Unmarshal(body, &txHistory); err != nil {
		return errorResponse(msg.GetID(), "failed to parse history"), nil
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > len(txHistory) {
		limit = len(txHistory)
	}

	entries := make([]WalletTxEntry, 0, limit)
	for i := 0; i < limit; i++ {
		tx := txHistory[i]
		direction, amount := h.classifyTransaction(tx, record.Address)
		entries = append(entries, WalletTxEntry{
			TxID:        tx.TxID,
			Direction:   direction,
			AmountSats:  amount,
			FeeSats:     tx.Fee,
			Confirmed:   tx.Status.Confirmed,
			BlockHeight: tx.Status.BlockHeight,
			BlockTime:   tx.Status.BlockTime,
		})
	}

	return successResponse(msg.GetID(), WalletGetHistoryResponse{
		WalletID:     req.WalletID,
		Transactions: entries,
	})
}

// ============================================================================
// Connection Payment Flow
// ============================================================================

// HandleSendToConnection resolves a peer's BTC address and sends payment.
// Strategy: check peer's public profile first, then request via messaging.
func (h *WalletHandler) HandleSendToConnection(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletSendToConnectionRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	if req.AmountSats <= 0 {
		return errorResponse(msg.GetID(), "amount must be positive"), nil
	}
	if req.FeeRate <= 0 {
		return errorResponse(msg.GetID(), "fee_rate must be positive"), nil
	}

	// Load the connection to get the peer's info
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return errorResponse(msg.GetID(), "connection not found"), nil
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return errorResponse(msg.GetID(), "invalid connection data"), nil
	}
	if conn.Status != "active" {
		return errorResponse(msg.GetID(), "connection is not active"), nil
	}

	// Strategy 1: Check peer's cached profile for a public BTC address
	peerAddress := h.findPeerBtcAddress(conn.PeerGUID)

	if peerAddress == "" {
		// Strategy 2: Request address from peer via encrypted messaging
		// Send btc_address_request to peer vault
		addrReq := BtcAddressContent{
			Network: "mainnet",
		}
		reqData, _ := json.Marshal(addrReq)
		if h.publisher != nil {
			_ = h.publisher.PublishToVault(ctx, conn.PeerGUID, "btc-address-request", reqData)
		}
		return errorResponse(msg.GetID(), "peer has no public BTC address — address request sent to peer; retry after they respond"), nil
	}

	// Build a send request using the resolved address
	sendReq := WalletSendRequest{
		WalletID:   req.WalletID,
		ToAddress:  peerAddress,
		AmountSats: req.AmountSats,
		FeeRate:    req.FeeRate,
	}
	sendPayload, _ := json.Marshal(sendReq)
	sendMsg := &IncomingMessage{
		Type:      msg.Type,
		RequestID: msg.RequestID,
		Payload:   sendPayload,
	}

	// Execute the send
	response, err := h.HandleSend(ctx, sendMsg)
	if err != nil {
		return response, err
	}

	// Send payment receipt to peer
	if response.Type == MessageTypeResponse {
		var sendResp WalletSendResponse
		if json.Unmarshal(response.Payload, &sendResp) == nil && sendResp.TxID != "" {
			receipt := BtcPaymentReceiptContent{
				TxID:       sendResp.TxID,
				AmountSats: req.AmountSats,
				FeeSats:    sendResp.FeeSats,
			}
			receiptData, _ := json.Marshal(receipt)
			if h.publisher != nil {
				_ = h.publisher.PublishToVault(ctx, conn.PeerGUID, "btc-payment-receipt", receiptData)
			}

			// Also publish to our app for conversation display
			if h.publisher != nil {
				appMsg := map[string]interface{}{
					"connection_id": req.ConnectionID,
					"content_type":  "btc_payment_receipt",
					"content":       receipt,
				}
				appData, _ := json.Marshal(appMsg)
				_ = h.publisher.PublishToApp(ctx, "message.btc-receipt", appData)
			}
		}
	}

	return response, nil
}

// HandleRequestPayment sends a payment request to a connection via encrypted messaging.
func (h *WalletHandler) HandleRequestPayment(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	var req WalletRequestPaymentRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return errorResponse(msg.GetID(), "invalid request: "+err.Error()), nil
	}

	if req.AmountSats <= 0 {
		return errorResponse(msg.GetID(), "amount must be positive"), nil
	}
	if req.ConnectionID == "" {
		return errorResponse(msg.GetID(), "connection_id is required"), nil
	}

	// Load wallet to get the receive address
	record, err := h.loadWallet(req.WalletID)
	if err != nil {
		return errorResponse(msg.GetID(), "wallet not found"), nil
	}

	// Load connection
	connData, err := h.storage.Get("connections/" + req.ConnectionID)
	if err != nil {
		return errorResponse(msg.GetID(), "connection not found"), nil
	}
	var conn ConnectionRecord
	if err := json.Unmarshal(connData, &conn); err != nil {
		return errorResponse(msg.GetID(), "invalid connection data"), nil
	}
	if conn.Status != "active" {
		return errorResponse(msg.GetID(), "connection is not active"), nil
	}

	// Build payment request content
	paymentReq := BtcPaymentRequestContent{
		AmountSats: req.AmountSats,
		Address:    record.Address,
		Memo:       req.Memo,
		WalletID:   req.WalletID,
	}
	paymentData, _ := json.Marshal(paymentReq)

	// Send to peer vault as a payment request message
	if h.publisher != nil {
		err = h.publisher.PublishToVault(ctx, conn.PeerGUID, "btc-payment-request", paymentData)
		if err != nil {
			return errorResponse(msg.GetID(), "failed to send payment request: "+err.Error()), nil
		}
	}

	// Also publish to our app for conversation display
	if h.publisher != nil {
		appMsg := map[string]interface{}{
			"connection_id": req.ConnectionID,
			"content_type":  "btc_payment_request",
			"content":       paymentReq,
		}
		appData, _ := json.Marshal(appMsg)
		_ = h.publisher.PublishToApp(ctx, "message.btc-request", appData)
	}

	// Log event
	if h.eventHandler != nil {
		h.eventHandler.LogEvent(ctx, &Event{
			EventType: EventTypePaymentRequested,
			Metadata: map[string]string{
				"wallet_id":     req.WalletID,
				"connection_id": req.ConnectionID,
				"amount_sats":   fmt.Sprintf("%d", req.AmountSats),
			},
		})
	}

	log.Info().
		Str("connection_id", req.ConnectionID).
		Int64("amount_sats", req.AmountSats).
		Msg("BTC payment request sent to connection")

	return successResponse(msg.GetID(), map[string]bool{"success": true})
}

// HandleIncomingAddressRequest handles a btc_address_request from a peer vault.
// Auto-responds with the user's primary (first non-archived) wallet address.
func (h *WalletHandler) HandleIncomingAddressRequest(ctx context.Context, msg *IncomingMessage) (*OutgoingMessage, error) {
	// Find the sender's owner space from the message subject
	senderGUID := msg.OwnerSpace

	wallets, err := h.loadAllWallets()
	if err != nil || len(wallets) == 0 {
		log.Warn().Msg("No wallets available to respond to address request")
		return successResponse(msg.GetID(), map[string]string{"status": "no_wallets"})
	}

	// Find first non-archived wallet
	var address string
	var network string
	for _, w := range wallets {
		if !w.IsArchived {
			address = w.Address
			network = w.Network
			break
		}
	}

	if address == "" {
		return successResponse(msg.GetID(), map[string]string{"status": "no_active_wallets"})
	}

	// Respond to the requesting peer
	addrResp := BtcAddressContent{
		Address: address,
		Network: network,
	}
	respData, _ := json.Marshal(addrResp)

	if h.publisher != nil && senderGUID != "" {
		_ = h.publisher.PublishToVault(ctx, senderGUID, "btc-address-response", respData)
	}

	log.Info().
		Str("peer", senderGUID).
		Str("address", address).
		Msg("Responded to BTC address request")

	return successResponse(msg.GetID(), map[string]string{"status": "sent"})
}

// findPeerBtcAddress checks a peer's cached profile for a public BTC address
func (h *WalletHandler) findPeerBtcAddress(peerGUID string) string {
	// Try to load cached peer profile
	profileData, err := h.storage.Get("profiles/peer/" + peerGUID)
	if err != nil {
		return ""
	}

	// Look for a BTC address in the profile's public keys
	var profile map[string]interface{}
	if err := json.Unmarshal(profileData, &profile); err != nil {
		return ""
	}

	// Check for btc_address in public_keys section
	if publicKeys, ok := profile["public_keys"].(map[string]interface{}); ok {
		if btcAddr, ok := publicKeys["btc_address"].(string); ok {
			return btcAddr
		}
	}

	return ""
}

// ============================================================================
// Internal Helper Methods
// ============================================================================

// nextAccountIndex finds the next available BIP44 account index
func (h *WalletHandler) nextAccountIndex() int {
	wallets, err := h.loadAllWallets()
	if err != nil {
		return 0
	}

	maxIndex := -1
	for _, w := range wallets {
		if w.AccountIndex > maxIndex {
			maxIndex = w.AccountIndex
		}
	}
	return maxIndex + 1
}

// loadWallet loads a wallet record from storage
func (h *WalletHandler) loadWallet(walletID string) (*WalletRecord, error) {
	data, err := h.storage.Get(walletStorageKey(walletID))
	if err != nil {
		return nil, fmt.Errorf("wallet not found: %w", err)
	}

	var record WalletRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to parse wallet: %w", err)
	}

	return &record, nil
}

// loadAllWallets loads all wallet records from storage using the index
func (h *WalletHandler) loadAllWallets() ([]WalletRecord, error) {
	ids, err := h.storage.GetIndex(walletIndexKey)
	if err != nil {
		// Index doesn't exist yet = no wallets
		return nil, nil
	}

	wallets := make([]WalletRecord, 0, len(ids))
	for _, id := range ids {
		data, err := h.storage.Get(walletStorageKey(id))
		if err != nil {
			continue
		}
		var record WalletRecord
		if err := json.Unmarshal(data, &record); err != nil {
			continue
		}
		wallets = append(wallets, record)
	}

	return wallets, nil
}

// findPrivateKey finds the private key for a wallet from the credential's CryptoKeys
func (h *WalletHandler) findPrivateKey(record *WalletRecord) ([]byte, error) {
	h.vaultState.mu.RLock()
	credential := h.vaultState.credential
	h.vaultState.mu.RUnlock()

	if credential == nil {
		return nil, fmt.Errorf("vault not unlocked")
	}

	// Re-derive the key from master secret using the wallet's account index
	// This is deterministic and more reliable than searching CryptoKeys by ID
	privKey, _, _, _, err := GenerateWalletKeypair(
		credential.VaultMasterSecret,
		record.AccountIndex,
		record.Network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to re-derive private key: %w", err)
	}

	return privKey, nil
}

// fetchUTXOs fetches unspent transaction outputs for a wallet
func (h *WalletHandler) fetchUTXOs(record *WalletRecord) ([]UTXO, error) {
	url := fmt.Sprintf("%s/address/%s/utxo", MempoolBaseURL(record.Network), record.Address)
	body, status, err := h.httpProxy.Get(url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("UTXO API returned status %d", status)
	}

	var utxos []UTXO
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, fmt.Errorf("failed to parse UTXOs: %w", err)
	}

	return utxos, nil
}

// buildTransaction selects UTXOs and constructs an unsigned transaction
func (h *WalletHandler) buildTransaction(
	utxos []UTXO,
	destScript []byte,
	changeScript []byte,
	amountSats int64,
	feeRate int,
	record *WalletRecord,
) (*BtcTransaction, error) {
	// Sort UTXOs largest first for simple selection
	sortUTXOsDescending(utxos)

	// Estimate fee: start with 1-in-2-out vsize, then adjust
	estimatedVsize := EstimateP2WPKHTxVsize(1, 2)
	estimatedFee := int64(feeRate) * int64(estimatedVsize)

	// SECURITY: Reject unreasonable fees
	maxFee := int64(100000) // 100k sats max fee
	if amountSats > 0 && estimatedFee > amountSats/10 && estimatedFee > maxFee {
		return nil, fmt.Errorf("estimated fee %d sats exceeds safety limit", estimatedFee)
	}

	totalNeeded := amountSats + estimatedFee

	// Select UTXOs
	var selectedUTXOs []UTXO
	var totalInput int64
	for _, utxo := range utxos {
		selectedUTXOs = append(selectedUTXOs, utxo)
		totalInput += utxo.Value
		if totalInput >= totalNeeded {
			break
		}
	}

	if totalInput < totalNeeded {
		return nil, fmt.Errorf("insufficient funds: have %d sats, need %d sats (amount: %d + fee: ~%d)",
			totalInput, totalNeeded, amountSats, estimatedFee)
	}

	// Recalculate fee with actual input count
	actualVsize := EstimateP2WPKHTxVsize(len(selectedUTXOs), 2)
	actualFee := int64(feeRate) * int64(actualVsize)

	// Build inputs
	inputs := make([]BtcTxInput, len(selectedUTXOs))
	for i, utxo := range selectedUTXOs {
		txid, err := ParseTxID(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("invalid UTXO txid: %w", err)
		}
		inputs[i] = BtcTxInput{
			TxID:     txid,
			Vout:     uint32(utxo.Vout),
			Sequence: 0xFFFFFFFD, // Enable RBF
			Value:    utxo.Value,
		}
	}

	// Build outputs
	outputs := []BtcTxOutput{
		{Value: amountSats, ScriptPubKey: destScript},
	}

	// Add change output if there's enough change to justify it (dust threshold ~546 sats)
	change := totalInput - amountSats - actualFee
	if change > 546 {
		outputs = append(outputs, BtcTxOutput{
			Value:        change,
			ScriptPubKey: changeScript,
		})
	} else {
		// Add dust to fee
		actualFee += change
	}

	return &BtcTransaction{
		Version:  2,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: 0,
	}, nil
}

// calculateFee calculates the fee from a transaction (sum of inputs - sum of outputs)
func (h *WalletHandler) calculateFee(tx *BtcTransaction) int64 {
	var totalIn, totalOut int64
	for _, in := range tx.Inputs {
		totalIn += in.Value
	}
	for _, out := range tx.Outputs {
		totalOut += out.Value
	}
	return totalIn - totalOut
}

// classifyTransaction determines if a transaction was sent or received relative to an address
func (h *WalletHandler) classifyTransaction(tx TxHistoryEntry, ourAddress string) (direction string, amount int64) {
	var receivedAmount, sentAmount int64

	// Check outputs for funds received by our address
	for _, vout := range tx.Vout {
		if vout.ScriptPubKeyAddr == ourAddress {
			receivedAmount += vout.Value
		}
	}

	// Check inputs for funds sent from our address
	for _, vin := range tx.Vin {
		if vin.Prevout != nil && vin.Prevout.ScriptPubKeyAddr == ourAddress {
			sentAmount += vin.Prevout.Value
		}
	}

	if sentAmount > receivedAmount {
		return "sent", sentAmount - receivedAmount
	}
	return "received", receivedAmount - sentAmount
}

// sortUTXOsDescending sorts UTXOs by value, largest first
func sortUTXOsDescending(utxos []UTXO) {
	for i := 0; i < len(utxos); i++ {
		for j := i + 1; j < len(utxos); j++ {
			if utxos[j].Value > utxos[i].Value {
				utxos[i], utxos[j] = utxos[j], utxos[i]
			}
		}
	}
}

// ============================================================================
// Response Helpers
// ============================================================================

func successResponse(requestID string, payload interface{}) (*OutgoingMessage, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}
	return &OutgoingMessage{
		Type:      MessageTypeResponse,
		RequestID: requestID,
		Payload:   data,
	}, nil
}

func errorResponse(requestID string, errMsg string) *OutgoingMessage {
	return &OutgoingMessage{
		Type:      MessageTypeError,
		RequestID: requestID,
		Error:     errMsg,
	}
}
