// Copyright 2025 PoT Consensus Authors
// This file implements the Proof-of-Tracing consensus engine.
//
// Proof of Tracing (PoT) is a dynamic consensus mechanism that selects block producers
// based on their historical performance and tracing capabilities rather than static authority.

package pot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	lru "github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

error The Configuration Is experiencing issues.
// =====error========
// PoT proof-of-tracing protocol constants
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce to vote adding validator
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce to vote removing validator

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages
var (
	errUnknownBlock           = errors.New("unknown block")
	errInvalidValidator       = errors.New("invalid validator")
	errInsufficientReputation = errors.New("insufficient reputation")
	errInvalidTracingProof    = errors.New("invalid tracing proof")
	errValidatorNotActive     = errors.New("validator not active")
	errRecentlyProposed       = errors.New("validator proposed recently")
	errMissingVanity          = errors.New("extra-data 32 byte vanity prefix missing")
	errMissingSignature       = errors.New("extra-data 65 byte signature suffix missing")
	errInvalidTimestamp       = errors.New("invalid timestamp")
	errUnauthorizedSigner     = errors.New("unauthorized signer")
	errRecentlySigned         = errors.New("recently signed")
	errInvalidVote            = errors.New("invalid vote")
	errInvalidVotingChain     = errors.New("invalid voting chain")
)

// SignerFn signs data for a validator
type SignerFn func(account accounts.Account, mimeType string, message []byte) ([]byte, error)

// Reputation metrics for validators
type ReputationMetrics struct {
	TotalBlocks      uint64  `json:"totalBlocks"`      // Total blocks proposed
	ValidBlocks      uint64  `json:"validBlocks"`      // Valid blocks proposed
	TotalTraces      uint64  `json:"totalTraces"`      // Total tracing attempts
	UptimeScore      float64 `json:"uptimeScore"`      // Uptime percentage
	LatencyScore     float64 `json:"latencyScore"`     // Average response time score
	LastActive       uint64  `json:"lastActive"`       // Last block number when active
}

// Calculate overall reputation score (0-100)
func (rm *ReputationMetrics) CalculateScore() float64 {
	if rm.TotalBlocks == 0 && rm.TotalTraces == 0 {
		return 0.0
	}

	// Block validation rate (30% weight)
	blockScore := 0.0
	if rm.TotalBlocks > 0 {
		blockScore = float64(rm.ValidBlocks) / float64(rm.TotalBlocks) * 30.0
	}

	// Tracing success rate (40% weight)
	traceScore := 0.0
	if rm.TotalTraces > 0 {
		traceScore = float64(rm.SuccessfulTraces) / float64(rm.TotalTraces) * 40.0
	}

	// Uptime score (20% weight)
	uptimeScore := rm.UptimeScore * 20.0

	// Latency score (10% weight)
	latencyScore := rm.LatencyScore * 10.0

	return blockScore + traceScore + uptimeScore + latencyScore
}

// Tracing challenge for validators
type TracingChallenge struct {
	TxHash     common.Hash `json:"txHash"`     // Transaction to trace
	Depth      uint8       `json:"depth"`      // Required tracing depth
	Timestamp  uint64      `json:"timestamp"`  // Challenge timestamp
	Difficulty uint8       `json:"difficulty"` // Challenge difficulty (1-10)
}

// // Tracing proof submitted by validators
// type TracingProof struct {
// 	Challenge      TracingChallenge `json:"challenge"`      // Original challenge
// 	Validator      common.Address   `json:"validator"`      // Validator address
// 	TraceSteps     []TraceStep      `json:"traceSteps"`     // Detailed trace steps
// 	Signature      []byte           `json:"signature"`      // Validator signature
// }

// Individual step in tracing proof
type TraceStep struct {
	TxHash      common.Hash    `json:"txHash"`      // Transaction hash
	BlockNumber uint64         `json:"blockNumber"` // Block number
	FromAddr    common.Address `json:"fromAddr"`    // From address
	ToAddr      common.Address `json:"toAddr"`      // To address
	Value       *big.Int       `json:"value"`       // Transaction value
	Proof       []byte         `json:"proof"`       // Merkle proof or similar
}

// ecrecover extracts the Ethereum account address from a signed header
func ecrecover(header *types.Header, sigcache *sigLRU) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address, nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// PoT is the proof-of-tracing consensus engine
type PoT struct {
	config *params.PoTConfig // Consensus engine configuration parameters
	db     ethdb.Database    // Database to store and retrieve snapshot checkpoints

	recents    *lru.Cache[common.Hash, *Snapshot] // Snapshots for recent block to speed up reorgs
	signatures *sigLRU                            // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer and proposals fields

	// PoT specific fields
	challenges map[common.Hash]*TracingChallenge // Active challenges
	rng        *rand.Rand                        // Random number generator

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a PoT proof-of-tracing consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.PoTConfig, db ethdb.Database) *PoT {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	// Allocate the snapshot caches and create the engine
	recents := lru.NewCache[common.Hash, *Snapshot](inmemorySnapshots)
	signatures := lru.NewCache[common.Hash, common.Address](inmemorySignatures)

	return &PoT{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
		challenges: make(map[common.Hash]*TracingChallenge),
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (pot *PoT) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, pot.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (pot *PoT) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	return pot.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers.
func (pot *PoT) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := pot.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// // verifyHeader checks whether a header conforms to the consensus rules.
// func (pot *PoT) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
// 	if header.Number == nil {
// 		return errUnknownBlock
// 	}

// 	// Don't waste time checking blocks from the future
// 	if header.Time > uint64(time.Now().Unix()) {
// 		return consensus.ErrFutureBlock
// 	}
error The configuration is experiencing issues.
// 	// Check that the extra-data contains both the vanity and signature
// 	if len(header.Extra) < extraVanity {
// 		return errMissingVanity
// 	}
// 	if len(header.Extra) < extraVanity+extraSeal {
// 		return errMissingSignature
// 	}

// 	// Ensure that the block doesn't contain any uncles which are meaningless in PoT
// 	if header.UncleHash != uncleHash {
// 		return errors.New("non empty uncle hash")
// 	}

// 	// All basic checks passed, verify cascading fields
// 	return pot.verifyCascadingFields(chain, header, parents)
// }

// verifyCascadingFields verifies all the header fields that are not standalone
func (pot *PoT) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+pot.config.Period > header.Time {
		return errInvalidTimestamp
	}

	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := pot.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// All basic checks passed, verify the seal and return
	return pot.verifySeal(snap, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (pot *PoT) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := pot.recents.Get(hash); ok {
			snap = s
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(pot.config, pot.signatures, pot.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// Genesis block case
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()
				log.Info("Processing genesis block", "extraData", hexutil.Encode(checkpoint.Extra))

				// // Extract signers from extraData
				// if len(checkpoint.Extra) < extraVanity+extraSeal {
				// 	log.Error("Genesis extraData too short", "length", len(checkpoint.Extra), "required", extraVanity+extraSeal)
				// 	return nil, errors.New("invalid genesis extraData")
				// }

				// signersData := checkpoint.Extra[extraVanity : len(checkpoint.Extra)-extraSeal]
				// if len(signersData)%common.AddressLength != 0 {
				// 	log.Error("Invalid signers data length", "length", len(signersData))
				// 	return nil, errors.New("invalid signers data")
				// }

				signers := make([]common.Address, len(signersData)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					copy(signers[i][:], signersData[i*common.AddressLength:])
					log.Info("Found genesis signer", "address", signers[i].Hex())
				}

				snap = newSnapshot(pot.config, pot.signatures, number, hash, signers)
				log.Info("Created genesis snapshot", "number", number, "hash", hash, "signers", len(signers))
				if snap != nil {
					pot.recents.Add(hash, snap)
				}
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	pot.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(pot.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (pot *PoT) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements.
func (pot *PoT) verifySeal(snap *Snapshot, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, pot.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
				return errRecentlyProposed
			}
		}
	}
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	// if !pot.fakeDiff {
	// 	inturn := snap.inturn(header.Number.Uint64(), signer)
	// 	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
	// 		return errors.New("wrong difficulty")
		// }
		// if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		// 	return errors.New("wrong difficulty")
		// }
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
error fix pot tracing

// Finalize implements consensus.Engine.
func (pot *PoT) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	// No block rewards in PoT, so the state remains as is
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (pot *PoT) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	if len(withdrawals) > 0 {
		return nil, errors.New("pot does not support withdrawals")
	}
	// Finalize block
	pot.Finalize(chain, header, state, txs, uncles, withdrawals)

	// // Assign the final state root to header
	// header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (pot *PoT) Authorize(signer common.Address, signFn SignerFn) {
	pot.lock.Lock()
	defer pot.lock.Unlock()

	log.Info("=== AUTHORIZING SIGNER ===", "signer", signer.Hex())
	pot.signer = signer
	pot.signFn = signFn
	log.Info("Signer authorized successfully", "signer", pot.signer.Hex())
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (pot *PoT) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if pot.config.Period == 0 && len(block.Transactions()) == 0 {
		return errors.New("sealing paused while waiting for transactions")
	}
	// Don't hold the signer fields for the entire sealing procedure
	pot.lock.RLock()
	signer, signFn := pot.signer, pot.signFn
	pot.lock.RUnlock()

	// // HACK: Auto-authorize if signer is zero address
	// if signer == (common.Address{}) {
	// 	log.Warn("Signer is zero address, attempting auto-authorization")

	// 	// Try to get etherbase from header.Coinbase or use a default
	// 	etherbase := common.HexToAddress("0xdc2436650c1ab0767ab0edc1267a219f54cf7147")

	// 	log.Info("Auto-authorizing etherbase", "address", etherbase.Hex())

		// Simple sign function for testing
	// Trong hàm Seal(), thay đổi autoSignFn:
	// Simple sign function for testing
	autoSignFn := func(account accounts.Account, mimeType string, message []byte) ([]byte, error) {
		log.Info("Auto-sign function called", "account", account.Address.Hex(), "messageLen", len(message))
		
		if err != nil {
			log.Error("Failed to parse private key", "err", err)
			return nil, err
		}
		
		// Verify private key matches account
		pubKey := privateKey.PublicKey
		address := crypto.PubkeyToAddress(pubKey)
		if address != account.Address {
			log.Error("Private key mismatch", "expected", account.Address.Hex(), "got", address.Hex())
		} else {
			log.Info("Private key verified", "address", address.Hex())
		}
		
		// Tạo hash của message
		hash := crypto.Keccak256(message)
		
		// Ký message
		signature, err := crypto.Sign(hash, privateKey)
		if err != nil {
			log.Error("Failed to sign message", "err", err)
			return nil, err
		}
		
		log.Info("Successfully signed message", "signatureLen", len(signature), "hash", common.BytesToHash(hash).Hex())
		return signature, nil
	}

		pot.Authorize(etherbase, autoSignFn)

		// Re-read signer after authorization
		pot.lock.RLock()
		signer, signFn = pot.signer, pot.signFn
		pot.lock.RUnlock()

		log.Info("After auto-authorization", "newSigner", signer.Hex())
	}
	// Bail out if we're unauthorized to sign a block
	snap, err := pot.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		log.Error("Failed to get snapshot for sealing", "number", number, "err", err)
		return err
	}

	// THÊM DEBUG LOGS NÀY:
	log.Info("=== SEALING DEBUG ===")
	log.Info("Block sealing info", "number", number, "signer", signer.Hex(), "parentHash", header.ParentHash.Hex())
	log.Info("Snapshot info", "snapshotNumber", snap.Number, "snapshotHash", snap.Hash.Hex(), "signersCount", len(snap.Signers))

	log.Info("Signers in sealing snapshot:")
	for authSigner := range snap.Signers {
		log.Info("  Authorized", "address", authSigner.Hex())
	}

	log.Info("Checking authorization", "signerToAuth", signer.Hex())

	// Giữ nguyên phần check authorization:
	if _, authorized := snap.Signers[signer]; !authorized {
		log.Error("=== AUTHORIZATION FAILED ===")
		log.Error("Signer not in snapshot", "signer", signer.Hex())
		log.Error("Available signers in snapshot:")
		for authSigner := range snap.Signers {
			log.Error("  Available", "address", authSigner.Hex())
		}
		return errUnauthorizedSigner
	} else {
		log.Info("=== AUTHORIZATION SUCCESS ===", "signer", signer.Hex())
	}

	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signer recently signed, waiting", "signer", signer.Hex(), "seen", seen, "limit", limit)
				return errors.New("signed recently, must wait for others")
			}
		}
	}
	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}

	log.Info("Proceeding with block sealing", "number", number, "signer", signer.Hex(), "delay", common.PrettyDuration(delay))

	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, PoTRLP(header))
	if err != nil {
		log.Error("Failed to sign block", "err", err)
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		log.Info("Block sealed successfully", "number", number, "hash", header.Hash().Hex())
		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm.

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := crypto.NewKeccakState()
	encodeSigHeader(hasher, header)
	hasher.Read(hash[:])
	return hash
}

// PoTRLP returns the rlp bytes which needs to be signed for the proof-of-tracing
// sealing.
func PoTRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength],
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}