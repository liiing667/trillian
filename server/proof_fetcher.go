// Copyright 2016 Google LLC. All Rights Reserved.
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

package server

import (
	"context"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/storage/tree"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
)

// nodeReader provides read-only access to the tree nodes.
type nodeReader interface {
	// GetMerkleNodes returns tree nodes by their IDs, in the requested order.
	GetMerkleNodes(ctx context.Context, ids []compact.NodeID) ([]tree.Node, error)
}

// fetchNodesAndBuildProof is used by both inclusion and consistency proofs. It fetches the nodes
// from storage and converts them into the proof proto that will be returned to the client.
// This includes rehashing where necessary to serve proofs for tree sizes between stored tree
// revisions. This code only relies on the nodeReader interface so can be tested without
// a complete storage implementation.
func fetchNodesAndBuildProof(ctx context.Context, nr nodeReader, hasher compact.HashFn, leafIndex uint64, pn proof.Nodes) (*trillian.Proof, error) {
	nodes, err := fetchNodes(ctx, nr, pn.IDs)
	if err != nil {
		return nil, err
	}

	h := make([][]byte, len(nodes))
	for i, node := range nodes {
		h[i] = node.Hash
	}
	proof, err := pn.Rehash(h, hasher)
	if err != nil {
		return nil, err
	}

	return &trillian.Proof{
		LeafIndex: int64(leafIndex),
		Hashes:    proof,
	}, nil
}

// fetchNodes obtains the nodes denoted by the given NodeFetch structs, and
// returns them after some validation checks.
func fetchNodes(ctx context.Context, nr nodeReader, ids []compact.NodeID) ([]tree.Node, error) {
	nodes, err := nr.GetMerkleNodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	if got, want := len(nodes), len(ids); got != want {
		return nil, fmt.Errorf("expected %d nodes from storage but got %d", want, got)
	}
	for i, node := range nodes {
		// Additional check that the correct node was returned.
		if got, want := node.ID, ids[i]; got != want {
			return nil, fmt.Errorf("expected node %v at proof pos %d but got %v", want, i, got)
		}
	}

	return nodes, nil
}

// rootHashAtSize computes the root hash of the tree at the requested size,
// using the same read-only snapshot as the proof nodes. The nodes forming the
// compact range for [0, size) are immutable once the tree has grown beyond
// that size, so reading them from a newer snapshot yields the same root as the
// historical version of the tree.
func rootHashAtSize(ctx context.Context, nr nodeReader, hasher merkle.LogHasher, size uint64) ([]byte, error) {
	if size == 0 {
		return hasher.EmptyRoot(), nil
	}

	ids := compact.RangeNodes(0, size, nil)
	nodes, err := fetchNodes(ctx, nr, ids)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, len(nodes))
	for i, node := range nodes {
		hashes[i] = node.Hash
	}

	r, err := (&compact.RangeFactory{Hash: hasher.HashChildren}).NewRange(0, size, hashes)
	if err != nil {
		return nil, err
	}
	return r.GetRootHash(nil)
}
