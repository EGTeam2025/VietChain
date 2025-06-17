// Copyright 2025 PoT Consensus Authors
// This file implements the RPC API for PoT consensus.

package pot

import (
	"context"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-tracing scheme.
type API struct {
	chain consensus.ChainHeaderReader
	pot   *PoT
}

// GetSnapshot retrieves the state snapshot at a given block.


// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSigners retrieves the list of authorized signers at the specified block.


// GetSignersAtHash retrieves the list of authorized signers at the specified block.
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// Proposals returns the current proposals the node tries to uphold and vote on.
func (api *API) Proposals() map[common.Address]bool {
	api.pot.lock.RLock()
	defer api.pot.lock.RUnlock()

	proposals := make(map[common.Address]bool)
	for address, auth := range api.pot.proposals {
		proposals[address] = auth
	}
	return proposals
}

// Propose injects a new authorization proposal that the signer will attempt to
// push through.
func (api *API) Propose(address common.Address, auth bool) {
	api.pot.lock.Lock()
	defer api.pot.lock.Unlock()

	api.pot.proposals[address] = auth
}

// Discard drops a currently running proposal, stopping the signer from casting
// further votes (either for or against).
func (api *API) Discard(address common.Address) {
	api.pot.lock.Lock()
	defer api.pot.lock.Unlock()

	delete(api.pot.proposals, address)
}

// Status returns the status of the last N blocks, returning the block numbers 
// and whether they were signed in-turn or out-of-turn.
func (api *API) Status() (*status, error) {
	var (
		numBlocks = uint64(64)
		header    = api.chain.CurrentHeader()
		diff      = uint64(0)
		optimals  = 0
	)
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	var (
		signers = snap.signers()
		end     = header.Number.Uint64()
		start   = end - numBlocks
	)
	if numBlocks > end {
		start = 1
	}
	for start <= end {
		// Retrieve the block header
		header = api.chain.GetHeaderByNumber(start)
		if header == nil {
			return nil, errUnknownBlock
		}
		// Check if the signer was in-turn or out-of-turn
		signer, err := api.pot.Author(header)
		if err != nil {
			return nil, err
		}
		if snap.inturn(start, signer) {
			optimals++
		}
		diff += header.Difficulty.Uint64()
		start++
	}
	return &status{
		InturnPercent: float64(optimals*100) / float64(numBlocks),
		SigningStatus: map[common.Address]int{},
		NumBlocks:     numBlocks,
		NumSigners:    len(signers),
		LatestSigner:  header.Coinbase,
		LatestNumber:  header.Number.Uint64(),
		LatestHash:    header.Hash(),
	}, nil
}


// PoT specific API methods

// GetValidators returns information about all validators in the network
func (api *API) GetValidators(number *rpc.BlockNumber) (map[common.Address]*Validator, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.Validators, nil
}

// GetActiveValidators returns the current active validator set based on reputation
func (api *API) GetActiveValidators(number *rpc.BlockNumber) ([]common.Address, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.ActiveSet, nil
}

// GetValidatorReputation returns the reputation score for a specific validator
func (api *API) GetValidatorReputation(address common.Address, number *rpc.BlockNumber) (float64, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return 0.0, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return 0.0, err
	}
	return snap.getValidatorReputation(address), nil
}

// GetActiveChallenges returns all active tracing challenges
func (api *API) GetActiveChallenges(number *rpc.BlockNumber) ([]*TracingChallenge, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.getActiveChallenges(), nil
}

// IsActiveValidator checks if an address is currently an active validator
func (api *API) IsActiveValidator(address common.Address, number *rpc.BlockNumber) (bool, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	return snap.isActiveValidator(address), nil
}

// SubmitTracingProof allows validators to submit tracing proofs for challenges
func (api *API) SubmitTracingProof(ctx context.Context, proof *TracingProof) error {
	// Validate the proof
	if proof == nil {
		return errInvalidTracingProof
	}
	
	// Verify the validator is authorized
	header := api.chain.CurrentHeader()
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return err
	}
	
	if !snap.isActiveValidator(proof.Validator) {
		return errValidatorNotActive
	}
	
	// TODO: Implement proof verification logic
	// This would include:
	// 1. Verify the signature
	// 2. Validate the trace steps
	// 3. Check completion time is reasonable
	// 4. Update validator reputation based on proof quality
	
	return nil
}

// CreateTracingChallenge creates a new tracing challenge for validators
func (api *API) CreateTracingChallenge(ctx context.Context, txHash common.Hash, depth uint8, difficulty uint8) (*TracingChallenge, error) {
	if depth == 0 || depth > tracingDepth {
		return nil, errInvalidTracingProof
	}
	
	challenge := &TracingChallenge{
		TxHash:     txHash,
		Depth:      depth,
		Timestamp:  uint64(ctx.Value("timestamp").(int64)),
		Difficulty: difficulty,
	}
	
	// Add to current challenges (this would typically be stored in state)
	header := api.chain.CurrentHeader()
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	
	snap.addTracingChallenge(challenge)
	
	return challenge, nil
}



// GetNetworkStats returns overall network statistics
func (api *API) GetNetworkStats(number *rpc.BlockNumber) (*NetworkStats, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.pot.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	
	stats := &NetworkStats{
		TotalValidators:     len(snap.Validators),
		ActiveValidators:    len(snap.ActiveSet),
		TotalSigners:        len(snap.Signers),
		CurrentEpoch:        snap.Epoch,
		ActiveChallenges:    len(snap.Challenges),
		AverageReputation:   0.0,
		MinReputation:       100.0,
		MaxReputation:       0.0,
	}
	
	var totalReputation float64
	for _, validator := range snap.Validators {
		score := validator.Reputation.CalculateScore()
		totalReputation += score
		if score < stats.MinReputation {
			stats.MinReputation = score
		}
		if score > stats.MaxReputation {
			stats.MaxReputation = score
		}
	}
	
	if len(snap.Validators) > 0 {
		stats.AverageReputation = totalReputation / float64(len(snap.Validators))
	}
	
	return stats, nil
}


func (api *API) validateTracingProof(proof *TracingProof) error {
	if proof == nil {
		return errInvalidTracingProof
	}
	
	// Check if proof has sufficient trace steps
	if len(proof.TraceSteps) < int(proof.Challenge.Depth) {
		return errInvalidTracingProof
	}
	
	// Check signature length
	if len(proof.Signature) != crypto.SignatureLength {
		return errInvalidTracingProof
	}
	
	// Check completion time is reasonable (not zero and not too high)
	if proof.CompletionTime == 0 || proof.CompletionTime > 60000 { // Max 60 seconds
		return errInvalidTracingProof
	}
	
	return nil
}