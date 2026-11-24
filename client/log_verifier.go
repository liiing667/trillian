// Copyright 2017 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// LogVerifier allows verification of output from Trillian Logs, both regular
// and pre-ordered; it is safe for concurrent use (as its contents are fixed
// after construction).
type LogVerifier struct {
	// hasher is the hash strategy used to compute nodes in the Merkle tree.
	hasher merkle.LogHasher
}

// NewLogVerifier returns an object that can verify output from Trillian Logs.
func NewLogVerifier(hasher merkle.LogHasher) *LogVerifier {
	return &LogVerifier{hasher: hasher}
}

// NewLogVerifierFromTree creates a new LogVerifier using the algorithms
// specified by a Trillian Tree object.
func NewLogVerifierFromTree(config *trillian.Tree) (*LogVerifier, error) {
	if config == nil {
		return nil, errors.New("client: NewLogVerifierFromTree(): nil config")
	}
	log, pLog := trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG
	if got := config.TreeType; got != log && got != pLog {
		return nil, fmt.Errorf("client: NewLogVerifierFromTree(): TreeType: %v, want %v or %v", got, log, pLog)
	}

	return NewLogVerifier(rfc6962.DefaultHasher), nil
}

// VerifyRoot verifies that newRoot is a valid append-only operation from
// trusted. If trusted.TreeSize is zero, a consistency proof is not needed.
//
// The returned root is only published after both the trusted and candidate
// root have a valid shape, and after the candidate has been proved to extend
// (or equal) the trusted root. In particular, a non-empty tree must have a
// root hash of exactly the hasher's output size.
func (c *LogVerifier) VerifyRoot(trusted *types.LogRootV1, newRoot *trillian.SignedLogRoot, consistency [][]byte) (*types.LogRootV1, error) {
	if trusted == nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted == nil")
	}
	if newRoot == nil {
		return nil, fmt.Errorf("VerifyRoot() error: newRoot == nil")
	}
	if c == nil || c.hasher == nil {
		return nil, fmt.Errorf("VerifyRoot() error: nil hasher")
	}

	var r types.LogRootV1
	if err := r.UnmarshalBinary(newRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted root %s, candidate root %s: %v",
			rootIdentity(trusted), rootIdentity(&r), err)
	}

	if trusted.TreeSize > 0 {
		if r.TreeSize < trusted.TreeSize {
			return nil, fmt.Errorf("VerifyRoot() error: trusted root %s, candidate root %s: tree size decreased from %d to %d",
				rootIdentity(trusted), rootIdentity(&r), trusted.TreeSize, r.TreeSize)
		}
	}

	// Refuse to build a trust chain on a root that could not have been
	// produced by the configured hasher. A zero-sized tree is the one
	// compatibility exception: it has no leaf-derived root, and some logs
	// persist either no hash or a non-canonical placeholder for it.
	if err := c.checkRootShape(trusted, "trusted"); err != nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted root %s, candidate root %s: %v",
			rootIdentity(trusted), rootIdentity(&r), err)
	}
	if err := c.checkRootShape(&r, "candidate"); err != nil {
		return nil, fmt.Errorf("VerifyRoot() error: trusted root %s, candidate root %s: %v",
			rootIdentity(trusted), rootIdentity(&r), err)
	}

	if trusted.TreeSize > 0 {
		// Verify consistency proof. This also checks that roots with equal
		// tree sizes are identical.
		if err := proof.VerifyConsistency(c.hasher, trusted.TreeSize, r.TreeSize, consistency, trusted.RootHash, r.RootHash); err != nil {
			return nil, fmt.Errorf("failed to verify consistency proof from trusted root %s to candidate root %s (%d hashes): %v",
				rootIdentity(trusted), rootIdentity(&r), len(consistency), err)
		}
	}
	return &r, nil
}

// VerifyInclusionByHash verifies that the inclusion proof for the given Merkle
// leafHash matches the given trusted root. The trusted root must describe a
// non-empty tree with a hash of the hasher's output size, and the proof index
// must be inside that tree. The proof is always evaluated at trusted.TreeSize,
// so a proof obtained for another tree size cannot be accepted by accident.
func (c *LogVerifier) VerifyInclusionByHash(trusted *types.LogRootV1, leafHash []byte, pf *trillian.Proof) error {
	if trusted == nil {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted == nil")
	}
	if pf == nil {
		return fmt.Errorf("VerifyInclusionByHash() error: proof == nil")
	}
	if c == nil || c.hasher == nil {
		return fmt.Errorf("VerifyInclusionByHash() error: nil hasher")
	}

	// An inclusion proof is only meaningful relative to a non-empty,
	// well-formed trusted root. Otherwise a proof could be checked against a
	// root that was never established by VerifyRoot.
	if err := c.checkRootShape(trusted, "trusted"); err != nil {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: %v",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize), err)
	}
	if trusted.TreeSize == 0 {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s is empty, %s",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize))
	}
	if pf.LeafIndex < 0 {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: proof index is negative",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize))
	}
	if uint64(pf.LeafIndex) >= trusted.TreeSize {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: proof index is outside the trusted tree",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize))
	}
	if got, want := len(leafHash), c.hasher.Size(); got != want {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: leaf hash length %d, want %d",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize), got, want)
	}
	for i, h := range pf.Hashes {
		if got, want := len(h), c.hasher.Size(); got != want {
			return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: proof hash %d length %d, want %d",
				rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize), i, got, want)
		}
	}

	if err := proof.VerifyInclusion(c.hasher, uint64(pf.LeafIndex), trusted.TreeSize, leafHash, pf.Hashes, trusted.RootHash); err != nil {
		return fmt.Errorf("VerifyInclusionByHash() error: trusted root %s, %s: %v",
			rootIdentity(trusted), proofIdentity(pf, trusted.TreeSize), err)
	}
	return nil
}

// checkRootShape validates the parts of a root that can be checked without
// knowing which tree it belongs to. A root for a non-empty tree must carry a
// hash of exactly the size produced by the verifier's hasher. An empty tree is
// deliberately left permissive for compatibility with logs that persist an
// empty or placeholder hash at size zero.
func (c *LogVerifier) checkRootShape(root *types.LogRootV1, role string) error {
	if root.TreeSize == 0 {
		return nil
	}
	if len(root.RootHash) == 0 {
		return fmt.Errorf("%s root hash is empty for tree size %d", role, root.TreeSize)
	}
	if got, want := len(root.RootHash), c.hasher.Size(); got != want {
		return fmt.Errorf("%s root hash length %d, want %d for tree size %d", role, got, want, root.TreeSize)
	}
	if allZero(root.RootHash) {
		return fmt.Errorf("%s root hash is all zero for tree size %d", role, root.TreeSize)
	}
	if bytes.Equal(root.RootHash, c.hasher.EmptyRoot()) {
		return fmt.Errorf("%s root hash is the empty-tree hash, but tree size is %d", role, root.TreeSize)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// rootIdentity renders a root's generation (tree size and hash) for errors.
// Keeping both sides of a rejected transition in the error makes it possible
// for a caller to tell which saved generation was compared with which
// candidate.
func rootIdentity(root *types.LogRootV1) string {
	if root == nil {
		return "<nil>"
	}
	return fmt.Sprintf("generation %d/%x", root.TreeSize, root.RootHash)
}

// proofIdentity renders the candidate proof's claimed position and tree size,
// so a rejection identifies both the trusted root and the proof that was
// checked against it.
func proofIdentity(pf *trillian.Proof, treeSize uint64) string {
	if pf == nil {
		return "proof <nil>"
	}
	return fmt.Sprintf("proof index %d, tree size %d, %d hashes", pf.LeafIndex, treeSize, len(pf.Hashes))
}
