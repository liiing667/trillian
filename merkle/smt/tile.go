// Copyright 2019 Google LLC. All Rights Reserved.
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

package smt

import (
	"fmt"

	"github.com/google/trillian/merkle/smt/node"
)

// Tile represents a sparse Merkle tree tile, i.e. a dense set of tree nodes
// located under a single "root" node at a distance not exceeding the tile
// height. A tile is identified by the ID of its root node. The Tile struct
// contains the list of non-empty leaf nodes, which can be used to reconstruct
// all the remaining inner nodes of the tile.
//
// Invariants of this structure that must be preserved at all times:
//   - ID is a prefix of Leaves' IDs, i.e. the nodes are in the same subtree.
//   - IDs of Leaves have the same length, i.e. the nodes are at the same level.
//   - Leaves are ordered by ID from left to right.
//   - IDs of Leaves are unique.
//
// Algorithms that create Tile structures must ensure that these invariants
// hold. Use NewNodesRow function for ordering nodes correctly.
type Tile struct {
	ID     node.ID
	Leaves NodesRow
}

// Merge returns a new tile which is a combination of this tile with the given
// updates. The resulting tile contains all the nodes from the updates, and all
// the nodes from the original tile not present in the updates.
//
// Both the current tile and the updates must satisfy all the Tile invariants
// documented on the Tile type: node IDs must be strictly below the tile root,
// all at the same depth, ordered from left to right, and unique. Merge
// verifies these invariants on both inputs regardless of whether the current
// tile is empty, and returns an error if any of them is violated. The returned
// tile owns its Leaves slice, i.e. it does not share the backing storage with
// either of the inputs, so subsequent mutations of the inputs do not affect
// the result.
func (t Tile) Merge(updates NodesRow) (Tile, error) {
	if err := t.Leaves.validate(t.ID); err != nil {
		return Tile{}, fmt.Errorf("tile leaves: %v", err)
	}
	if len(updates) == 0 {
		return Tile{ID: t.ID, Leaves: t.Leaves.clone()}, nil
	}
	if err := updates.validate(t.ID); err != nil {
		return Tile{}, fmt.Errorf("updates: %v", err)
	}
	if len(t.Leaves) > 0 {
		if at, want := updates[0].ID.BitLen(), t.Leaves[0].ID.BitLen(); at != want {
			return Tile{}, fmt.Errorf("updates are at depth %d, want %d", at, want)
		}
	}
	if len(t.Leaves) == 0 {
		return Tile{ID: t.ID, Leaves: updates.clone()}, nil
	}
	return Tile{ID: t.ID, Leaves: merge(t.Leaves.clone(), updates.clone())}, nil
}

// merge merges two sorted slices of nodes into one sorted slice. If a node ID
// exists in both slices, then the one from the updates slice is taken, i.e. it
// overrides the node from the nodes slice.
func merge(nodes, updates NodesRow) NodesRow {
	res := make([]Node, 0, len(nodes)+len(updates))
	i := 0
	for _, u := range updates {
		for ; i < len(nodes); i++ {
			if c := compareHorizontal(nodes[i].ID, u.ID); c < 0 {
				res = append(res, nodes[i])
			} else if c > 0 {
				break
			}
		}
		res = append(res, u)
	}
	return append(res, nodes[i:]...)
}

// rootHash recomputes the hash of the tile root from the tile leaves. All the
// sibling subtrees missing from Leaves are assumed to be empty. The tile must
// satisfy the invariants documented on the Tile type.
//
// It can be used to verify that persisted tile nodes were not tampered with by
// comparing the recomputed hash against the tile root hash recorded in the
// parent tile.
func (t Tile) rootHash(l Layout, h mapHasher) ([]byte, error) {
	if len(t.Leaves) == 0 {
		return h.hashEmpty(t.ID), nil
	}
	top := t.ID.BitLen()
	_, height := l.Locate(top + 1)
	leaves := make([]Node, len(t.Leaves))
	copy(leaves, t.Leaves)
	hs, err := NewHStar3(leaves, h.mh.HashChildren, top+height, top)
	if err != nil {
		return nil, err
	}
	upd, err := hs.Update(emptyHashes{h: h})
	if err != nil {
		return nil, err
	} else if len(upd) != 1 {
		return nil, fmt.Errorf("expected a single root update, got %d", len(upd))
	}
	return upd[0].Hash, nil
}

// scan visits all non-empty nodes of the tile except the root. The order of
// node visits is arbitrary.
func (t Tile) scan(l Layout, h mapHasher, visit func(Node)) error {
	top := t.ID.BitLen()
	_, height := l.Locate(top + 1)
	// TODO(pavelkalinnikov): Remove HStar3 side effects, to avoid copying here.
	// Currently, the Update method modifies the nodes given to NewHStar3.
	leaves := make([]Node, len(t.Leaves))
	copy(leaves, t.Leaves)
	hs, err := NewHStar3(leaves, h.mh.HashChildren, top+height, top)
	if err != nil {
		return err
	}
	_, err = hs.Update(emptyHashes{h: h, visit: visit})
	return err
}

// emptyHashes is a NodeAccessor used for computing node hashes of a tile.
type emptyHashes struct {
	h     mapHasher
	visit func(Node)
}

// Get returns an empty hash for the given root node ID.
func (e emptyHashes) Get(id node.ID) ([]byte, error) {
	return e.h.hashEmpty(id), nil
}

// Set calls the visitor callback for the given node and hash.
func (e emptyHashes) Set(id node.ID, hash []byte) {
	if e.visit == nil {
		return
	}
	e.visit(Node{ID: id, Hash: hash})
}
