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
	"bytes"
	"fmt"
	"sort"

	"github.com/google/trillian/merkle/smt/node"
)

// TileSet represents a set of Merkle tree tiles and the corresponding nodes.
// This type is not thread-safe.
//
// TODO(pavelkalinnikov): Make it immutable.
type TileSet struct {
	layout Layout
	tiles  map[node.ID]NodesRow
	hashes map[node.ID][]byte
	h      mapHasher
}

// NewTileSet creates an empty TileSet with the given tree parameters.
func NewTileSet(treeID int64, hasher Hasher, layout Layout) *TileSet {
	tiles := make(map[node.ID]NodesRow)
	hashes := make(map[node.ID][]byte)
	h := bindHasher(hasher, treeID)
	return &TileSet{layout: layout, tiles: tiles, hashes: hashes, h: h}
}

// Hashes returns a map containing all node hashes keyed by node IDs.
func (t *TileSet) Hashes() map[node.ID][]byte {
	return t.hashes
}

// Add puts the given tile into the set. Not thread-safe.
//
// TODO(pavelkalinnikov): Take a whole list of Tiles instead.
func (t *TileSet) Add(tile Tile) error {
	if _, ok := t.tiles[tile.ID]; ok {
		return fmt.Errorf("tile already exists: %v", tile.ID)
	}
	t.tiles[tile.ID] = tile.Leaves
	return tile.scan(t.layout, t.h, func(node Node) {
		t.hashes[node.ID] = node.Hash
	})
}

// TileSetMutation accumulates tree tiles that need to be updated. This type is
// not thread-safe.
type TileSetMutation struct {
	read  *TileSet
	tiles map[node.ID][]Node
}

// NewTileSetMutation creates a mutation which is based off the provided
// TileSet. This means that each modification is checked against the hashes in
// this set, and is applied if it does change the hash.
func NewTileSetMutation(ts *TileSet) *TileSetMutation {
	tiles := make(map[node.ID][]Node)
	return &TileSetMutation{read: ts, tiles: tiles}
}

// Set updates the hash of the given tree node. Not thread-safe.
//
// TODO(pavelkalinnikov): Elaborate on the expected order of Set calls.
// Currently, Build method sorts nodes to allow any order, but it can be
// avoided.
func (t *TileSetMutation) Set(id node.ID, hash []byte) {
	if bytes.Equal(t.read.hashes[id], hash) {
		return // Nothing changed.
	}
	d, height := t.read.layout.Locate(id.BitLen())
	if d+height != id.BitLen() {
		return // Not a leaf node of a tile.
	}
	root := id.Prefix(d)
	t.tiles[root] = append(t.tiles[root], Node{ID: id, Hash: hash})
}

// Build returns the full set of tiles modified by this mutation.
func (t *TileSetMutation) Build() ([]Tile, error) {
	res := make([]Tile, 0, len(t.tiles))
	for id, upd := range t.tiles {
		sort.Slice(upd, func(i, j int) bool {
			return compareHorizontal(upd[i].ID, upd[j].ID) < 0
		})
		tile := Tile{ID: id}
		if had, ok := t.read.tiles[id]; ok {
			tile.Leaves = had
		}
		var err error
		// First enforce the structural Tile invariants on both the persisted
		// nodes and the updates, rejecting cross-subtree, wrong-depth, unsorted,
		// and duplicate nodes before any hash is recomputed.
		tile, err = tile.Merge(upd)
		if err != nil {
			return nil, err
		}
		rootDepth, _ := t.read.layout.Locate(id.BitLen())
		if had, ok := t.read.tiles[id]; ok && len(had) > 0 && rootDepth != 0 {
			// Then re-verify the persisted tile against the root hash recorded in
			// the parent tile, so that tampered persisted nodes can never
			// participate in root hash computation. Tiles of the topmost tier
			// (rootDepth == 0) have no parent tile with a recorded root hash, so
			// they are the trust boundary.
			want, ok := t.read.hashes[id]
			if !ok {
				return nil, fmt.Errorf("tile %v: no persisted root hash found for verification", id)
			}
			got, err := Tile{ID: id, Leaves: had}.rootHash(t.read.layout, t.read.h)
			if err != nil {
				return nil, fmt.Errorf("recomputing root hash of tile %v: %v", id, err)
			}
			if !bytes.Equal(got, want) {
				return nil, fmt.Errorf("tile %v: persisted root hash %x does not match the recomputed one %x", id, want, got)
			}
		}
		res = append(res, tile)
	}
	return res, nil
}
