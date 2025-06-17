// Copyright 2025 PoT Consensus Authors
// This file implements the snapshot management for PoT consensus.

package pot

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/exp/slices"
)

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes)
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account
}

// Tally is a simple vote tally to keep the current score of votes.
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal
}

type sigLRU = lru.Cache[common.Hash, common.Address]

// Validator represents a network participant with reputation metrics
type Validator struct {
	Address     common.Address    `json:"address"`     // Validator address
	Reputation  ReputationMetrics `json:"reputation"`  // Reputation metrics
	IsActive    bool              `json:"isActive"`    // Currently active status
	JoinedBlock uint64            `json:"joinedBlock"` // Block when validator joined
	LastSeen    uint64            `json:"lastSeen"`    // Last block when validator was seen
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.PoTConfig // Consensus engine parameters to fine tune behavior
	sigcache *sigLRU           // Cache of recent block signatures to speed up ecrecover

	Number     uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Signers    map[common.Address]struct{} `json:"signers"`    // Set of authorized signers at this moment
	Recents    map[uint64]common.Address   `json:"recents"`    // Set of recent signers for spam protections
	Votes      []*Vote                     `json:"votes"`      // List of votes cast in chronological order
	Tally      map[common.Address]Tally    `json:"tally"`      // Current vote tally to avoid recalculating
	Validators map[common.Address]*Validator `json:"validators"` // PoT: All validators with reputation
	ActiveSet  []common.Address            `json:"activeSet"`  // PoT: Current active validators based on reputation
	Challenges map[common.Hash]*TracingChallenge `json:"challenges"` // PoT: Active tracing challenges
	Epoch      uint64                      `json:"epoch"`      // PoT: Current epoch number
}

// newSnapshot creates a new snapshot with the specified startup parameters.
func newSnapshot(config *params.PoTConfig, sigcache *sigLRU, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	snap := &Snapshot{
        config:     config,
        sigcache:   sigcache,
        Number:     number,
        Hash:       hash,
        Signers:    make(map[common.Address]struct{}),
        Recents:    make(map[uint64]common.Address),
        Tally:      make(map[common.Address]Tally),
        Validators: make(map[common.Address]*Validator),
        ActiveSet:  make([]common.Address, 0),
        Challenges: make(map[common.Hash]*TracingChallenge),
        Epoch:      number / config.Epoch,
    }
	for _, signer := range signers {
        snap.Signers[signer] = struct{}{}
        // Initialize validators with basic reputation
        snap.Validators[signer] = &Validator{
            Address:     signer,
            Reputation:  ReputationMetrics{UptimeScore: 1.0, LatencyScore: 1.0},
            IsActive:    true,
            JoinedBlock: number,
            LastSeen:    number,
        }
        snap.ActiveSet = append(snap.ActiveSet, signer)
    }
    return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.PoTConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append(rawdb.CliqueSnapshotPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append(rawdb.CliqueSnapshotPrefix, s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:     s.config,
		sigcache:   s.sigcache,
		Number:     s.Number,
		Hash:       s.Hash,
		Signers:    make(map[common.Address]struct{}),
		Recents:    make(map[uint64]common.Address),
		Votes:      make([]*Vote, len(s.Votes)),
		Tally:      make(map[common.Address]Tally),
		Validators: make(map[common.Address]*Validator),
		ActiveSet:  make([]common.Address, len(s.ActiveSet)),
		Challenges: make(map[common.Hash]*TracingChallenge),
		Epoch:      s.Epoch,
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	for addr, validator := range s.Validators {
		cpy.Validators[addr] = &Validator{
			Address:     validator.Address,
			Reputation:  validator.Reputation,
			IsActive:    validator.IsActive,
			JoinedBlock: validator.JoinedBlock,
			LastSeen:    validator.LastSeen,
		}
	}
	copy(cpy.ActiveSet, s.ActiveSet)
	for hash, challenge := range s.Challenges {
		cpy.Challenges[hash] = &TracingChallenge{
			TxHash:     challenge.TxHash,
			Depth:      challenge.Depth,
			Timestamp:  challenge.Timestamp,
			Difficulty: challenge.Difficulty,
		}
	}
	copy(cpy.Votes, s.Votes)

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context.
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Signers[address]
	return (signer && !authorize) || (!signer && authorize)
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
			snap.Epoch = number / s.config.Epoch
		}
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = signer

		// PoT: Update validator reputation and activity
		snap.updateValidatorMetrics(signer, header, true)

		// Header authorized, discard any previous votes from the signer
		for i, vote := range snap.Votes {
			if vote.Signer == signer && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // only one vote allowed
			}
		}
		
		// Tally up the new vote from the signer
		var authorize bool
		switch {
		case bytes.Equal(header.Nonce[:], nonceAuthVote):
			authorize = true
		case bytes.Equal(header.Nonce[:], nonceDropVote):
			authorize = false
		default:
			// Not a vote, continue processing - THIS IS NORMAL!
			continue // ← FIXED: Changed from "return nil, errInvalidVote" to "continue"
		}
		
		if snap.cast(header.Coinbase, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Signer:    signer,
				Block:     number,
				Address:   header.Coinbase,
				Authorize: authorize,
			})
		}
		
		// If the vote passed, update the list of signers
		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Signers)/2 {
			if tally.Authorize {
				snap.Signers[header.Coinbase] = struct{}{}
				// PoT: Add new validator
				snap.addValidator(header.Coinbase, number)
			} else {
				delete(snap.Signers, header.Coinbase)
				// PoT: Remove validator
				snap.removeValidator(header.Coinbase)

				// Signer list shrunk, delete any leftover recent caches
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signer cast
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.Coinbase {
						// Uncast the vote from the cached tally
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase)
		}

		// PoT: Update active validator set based on reputation
		if number%100 == 0 { // Every 100 blocks, recalculate active set
			snap.updateActiveSet()
		}

		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// PoT specific methods

// updateValidatorMetrics updates the reputation metrics for a validator
func (s *Snapshot) updateValidatorMetrics(signer common.Address, header *types.Header, successful bool) {
	validator, exists := s.Validators[signer]
	if !exists {
		// Create new validator
		validator = &Validator{
			Address:     signer,
			Reputation:  ReputationMetrics{UptimeScore: 1.0, LatencyScore: 1.0},
			IsActive:    true,
			JoinedBlock: header.Number.Uint64(),
			LastSeen:    header.Number.Uint64(),
		}
		s.Validators[signer] = validator
	}

	// Update metrics
	validator.Reputation.TotalBlocks++
	if successful {
		validator.Reputation.ValidBlocks++
	}
	validator.LastSeen = header.Number.Uint64()

	// Calculate uptime based on recent activity
	blocksSinceJoin := header.Number.Uint64() - validator.JoinedBlock
	if blocksSinceJoin > 0 {
		expectedBlocks := blocksSinceJoin / uint64(len(s.Signers))
		if expectedBlocks > 0 {
			validator.Reputation.UptimeScore = float64(validator.Reputation.TotalBlocks) / float64(expectedBlocks)
			if validator.Reputation.UptimeScore > 1.0 {
				validator.Reputation.UptimeScore = 1.0
			}
		}
	}
}

// addValidator adds a new validator to the snapshot
func (s *Snapshot) addValidator(address common.Address, blockNumber uint64) {
	if _, exists := s.Validators[address]; !exists {
		s.Validators[address] = &Validator{
			Address:     address,
			Reputation:  ReputationMetrics{UptimeScore: 0.5, LatencyScore: 0.5}, // Start with lower reputation
			IsActive:    true,
			JoinedBlock: blockNumber,
			LastSeen:    blockNumber,
		}
	}
}

// removeValidator removes a validator from the snapshot
func (s *Snapshot) removeValidator(address common.Address) {
	if validator, exists := s.Validators[address]; exists {
		validator.IsActive = false
	}
	// Remove from active set
	for i, addr := range s.ActiveSet {
		if addr == address {
			s.ActiveSet = append(s.ActiveSet[:i], s.ActiveSet[i+1:]...)
			break
		}
	}
}

// updateActiveSet recalculates the active validator set based on reputation scores
func (s *Snapshot) updateActiveSet() {
	type validatorScore struct {
		address common.Address
		score   float64
	}

	var candidates []validatorScore
	for addr, validator := range s.Validators {
		if validator.IsActive && s.isEligible(validator) {
			score := validator.Reputation.CalculateScore()
			candidates = append(candidates, validatorScore{addr, score})
		}
	}

	// Sort by reputation score (descending)
	slices.SortFunc(candidates, func(a, b validatorScore) int {
		if a.score > b.score {
			return -1
		}
		if a.score < b.score {
			return 1
		}
		return 0
	})

	// Select top validators up to maxValidators
	maxActive := int(s.config.MaxCandidates) // Use MaxCandidates from config
	if maxActive > len(candidates) {
		maxActive = len(candidates)
	}

	s.ActiveSet = make([]common.Address, maxActive)
	for i := 0; i < maxActive; i++ {
		s.ActiveSet[i] = candidates[i].address
	}
}

// isEligible checks if a validator meets the minimum requirements
func (s *Snapshot) isEligible(validator *Validator) bool {
	score := validator.Reputation.CalculateScore()
	return score >= float64(s.config.MinTraceScore) // Use MinTraceScore from config
}

// signers retrieves the list of authorized signers in ascending order.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	slices.SortFunc(sigs, common.Address.Cmp)
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	// PoT modification: Use active set instead of all signers
	signers := s.ActiveSet
	if len(signers) == 0 {
		signers = s.signers() // Fallback to all signers if active set is empty
	}
	
	offset := 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	if offset >= len(signers) {
		return false // Signer not in active set
	}
	return (number % uint64(len(signers))) == uint64(offset)
}

// Additional PoT snapshot methods

// getValidatorReputation returns the reputation score for a validator
func (s *Snapshot) getValidatorReputation(address common.Address) float64 {
	if validator, exists := s.Validators[address]; exists {
		return validator.Reputation.CalculateScore()
	}
	return 0.0
}

// isActiveValidator checks if an address is in the current active set
func (s *Snapshot) isActiveValidator(address common.Address) bool {
	for _, active := range s.ActiveSet {
		if active == address {
			return true
		}
	}
	return false
}

// addTracingChallenge adds a new tracing challenge to the snapshot
func (s *Snapshot) addTracingChallenge(challenge *TracingChallenge) {
	hash := common.BytesToHash(challenge.TxHash[:])
	s.Challenges[hash] = challenge
}

// removeTracingChallenge removes a completed challenge
func (s *Snapshot) removeTracingChallenge(challengeHash common.Hash) {
	delete(s.Challenges, challengeHash)
}

// getActiveChallenges returns all active challenges
func (s *Snapshot) getActiveChallenges() []*TracingChallenge {
	challenges := make([]*TracingChallenge, 0, len(s.Challenges))
	for _, challenge := range s.Challenges {
		challenges = append(challenges, challenge)
	}
	return challenges
}