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
	"reflect"
	"strings"
	"testing"

	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/merkle/smt/node"
)

func TestTileSetAdd(t *testing.T) {
	hasher := coniks.Default
	l := NewLayout([]uint{8, 8})

	existing := Tile{
		ID:     node.NewID("\x00", 8),
		Leaves: []Node{{ID: node.NewID("\x00\x05", 16)}},
	}
	for _, tc := range []struct {
		tile    Tile
		wantErr string
	}{
		{tile: Tile{ID: node.NewID("\x01", 8)}},
		{tile: Tile{ID: node.NewID("\x00", 8)}, wantErr: "exists"},
		{
			tile: Tile{
				ID:     node.NewID("\x01", 8),
				Leaves: []Node{{ID: node.NewID("\x00\x05\x00", 24)}},
			},
			wantErr: "invalid depth",
		},
	} {
		t.Run("", func(t *testing.T) {
			ts := NewTileSet(0, hasher, l)
			if err := ts.Add(existing); err != nil {
				t.Fatalf("Add: %v", err)
			}
			got := ""
			if err := ts.Add(tc.tile); err != nil {
				got = err.Error()
			}
			if want := tc.wantErr; len(want) == 0 && len(got) != 0 {
				t.Errorf("Add: %v", got)
			} else if len(want) != 0 && !strings.Contains(got, want) {
				t.Errorf("Add: err=%q; want err containing %q", got, want)
			}
		})
	}
}

func TestTileSetHashes(t *testing.T) {
	l := NewLayout([]uint{8, 8})
	ts := NewTileSet(0, coniks.Default, l)

	count := 0
	for i, tc := range []struct {
		tile  Tile
		added int
	}{
		{tile: Tile{ID: node.NewID("\x02", 8), Leaves: nil}, added: 0},
		{
			tile: Tile{
				ID:     node.NewID("\x00", 8),
				Leaves: []Node{{ID: node.NewID("\x00\x01", 16)}},
			},
			added: 8,
		},
		{
			tile: Tile{Leaves: []Node{
				{ID: node.NewID("\x00", 8)},
				{ID: node.NewID("\x02", 8)},
			}},
			added: 10,
		},
	} {
		if err := ts.Add(tc.tile); err != nil {
			t.Fatalf("Add(%d): %v", i, err)
		}
		count += tc.added
		// TODO(pavelkalinnikov): Check the nodes containment.
		if got, want := len(ts.Hashes()), count; got != want {
			t.Fatalf("Hashes(%d): got %d nodes, want %d", i, got, want)
		}
	}
}

func TestTileSetMutationBuild(t *testing.T) {
	l := NewLayout([]uint{8, 8})
	ids := []node.ID{
		node.NewID("\x00\x00", 16),
		node.NewID("\x00\x70", 16),
		node.NewID("\x01\x01", 16),
		node.NewID("\xFF\xFF", 16),
		node.NewID("\x77\x77", 16),
		node.NewID("\x77\x88", 16),
	}
	ts := NewTileSet(0, coniks.Default, l)
	for _, tile := range []Tile{
		{Leaves: []Node{ // Root tile.
			{ID: ids[0].Prefix(8), Hash: []byte("hash_00")},
			{ID: ids[2].Prefix(8), Hash: []byte("hash_01")},
			{ID: ids[3].Prefix(8), Hash: []byte("hash_FF")},
		}},
		{ // Tile 0x00.
			ID: ids[0].Prefix(8),
			Leaves: []Node{
				{ID: ids[0], Hash: []byte("hash_0000")},
				{ID: ids[1], Hash: []byte("hash_0070")},
			},
		},
		{ // Tile 0x01.
			ID:     ids[2].Prefix(8),
			Leaves: []Node{{ID: ids[2], Hash: []byte("hash_0101")}},
		},
		{ // Tile 0xFF.
			ID:     ids[3].Prefix(8),
			Leaves: []Node{{ID: ids[3], Hash: []byte("hash_FFFF")}},
		},
	} {
		if err := ts.Add(tile); err != nil {
			t.Fatalf("Add(%v): %v", tile.ID, err)
		}
	}

	for _, tc := range []struct {
		upd  []Node             // Node updates.
		want map[node.ID][]Node // Updated tiles.
	}{
		{upd: nil, want: make(map[node.ID][]Node)},
		{ // Updating the hash with the old value.
			upd:  []Node{{ID: ids[0], Hash: []byte("hash_0000")}},
			want: make(map[node.ID][]Node), // Tiles are intact.
		},
		{ // Ignoring non-leaf node updates for tiles.
			upd:  []Node{{ID: ids[0].Prefix(1), Hash: []byte("root")}},
			want: make(map[node.ID][]Node),
		},
		{ // Updating a non-existing node of a non-existing tile.
			upd: []Node{{ID: ids[4], Hash: []byte("new_7777")}},
			want: map[node.ID][]Node{
				ids[4].Prefix(8): {{ID: ids[4], Hash: []byte("new_7777")}},
			},
		},
		{ // Updating an existing node.
			upd: []Node{{ID: ids[0], Hash: []byte("new_0000")}},
			want: map[node.ID][]Node{
				ids[0].Prefix(8): {
					{ID: ids[0], Hash: []byte("new_0000")},
					{ID: ids[1], Hash: []byte("hash_0070")},
				},
			},
		},
		{ // Updating nodes of an existing tile.
			upd: []Node{{ID: ids[0].Sibling(), Hash: []byte("new_0001")}},
			want: map[node.ID][]Node{
				ids[0].Prefix(8): {
					{ID: ids[0], Hash: []byte("hash_0000")},
					{ID: ids[0].Sibling(), Hash: []byte("new_0001")},
					{ID: ids[1], Hash: []byte("hash_0070")},
				},
			},
		},
		{ // Multiple updates in order.
			upd: []Node{
				{ID: ids[0], Hash: []byte("new_0000")},
				{ID: ids[1], Hash: []byte("new_0001")},
			},
			want: map[node.ID][]Node{
				ids[0].Prefix(8): {
					{ID: ids[0], Hash: []byte("new_0000")},
					{ID: ids[1], Hash: []byte("new_0001")},
				},
			},
		},
		{ // Multiple updates out of order.
			upd: []Node{
				{ID: ids[1], Hash: []byte("new_0001")},
				{ID: ids[0], Hash: []byte("new_0000")},
			},
			want: map[node.ID][]Node{
				ids[0].Prefix(8): {
					{ID: ids[0], Hash: []byte("new_0000")},
					{ID: ids[1], Hash: []byte("new_0001")},
				},
			},
		},
		{ // Multiple updates of a non-existing tile in order.
			upd: []Node{
				{ID: ids[4], Hash: []byte("new_7777")},
				{ID: ids[5], Hash: []byte("new_7788")},
			},
			want: map[node.ID][]Node{
				ids[4].Prefix(8): {
					{ID: ids[4], Hash: []byte("new_7777")},
					{ID: ids[5], Hash: []byte("new_7788")},
				},
			},
		},
		{ // Multiple updates of a non-existing tile out of order.
			upd: []Node{
				{ID: ids[5], Hash: []byte("new_7788")},
				{ID: ids[4], Hash: []byte("new_7777")},
			},
			want: map[node.ID][]Node{
				ids[4].Prefix(8): {
					{ID: ids[4], Hash: []byte("new_7777")},
					{ID: ids[5], Hash: []byte("new_7788")},
				},
			},
		},
		{ // Updating multiple existing tiles.
			upd: []Node{
				{ID: ids[0], Hash: []byte("new_0000")},
				{ID: ids[2], Hash: []byte("new_0101")},
			},
			want: map[node.ID][]Node{
				ids[0].Prefix(8): {
					{ID: ids[0], Hash: []byte("new_0000")},
					{ID: ids[1], Hash: []byte("hash_0070")},
				},
				ids[2].Prefix(8): {
					{ID: ids[2], Hash: []byte("new_0101")},
				},
			},
		},
	} {
		t.Run("", func(t *testing.T) {
			m := NewTileSetMutation(ts)
			for _, node := range tc.upd {
				m.Set(node.ID, node.Hash)
			}
			tiles, err := m.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			got := make(map[node.ID][]Node, len(tiles))
			for _, tile := range tiles {
				got[tile.ID] = tile.Leaves
			}
			if want := tc.want; !reflect.DeepEqual(got, want) {
				t.Logf("%v", got)
				t.Logf("%v", want)
				t.Fatalf("Tile mismatch: got %d tiles, want %d other ones", len(got), len(want))
			}
		})
	}
}

func TestTileSetMutationBuildVerifiesRootHash(t *testing.T) {
	l := NewLayout([]uint{8, 8, 8})
	// The verified tile is the middle-tier tile rooted at 16 bits; updates at
	// its 16-bit leaf level make Build load and re-check this persisted tile.
	tileID := node.NewID("\x00\x00", 16)
	id00 := node.NewID("\x00\x00\x00", 24)
	id70 := node.NewID("\x00\x00\x70", 24)
	id0000 := id00
	id0070 := id70

	newSet := func() *TileSet {
		ts := NewTileSet(0, coniks.Default, l)
		// Root tile stores the expected root hash of the 8-bit subtree as one
		// of its leaves; the 8-bit tile below holds the hash of the 16-bit tile
		// root that gets re-verified.
		root8 := tileID.Prefix(8)
		if err := ts.Add(Tile{Leaves: []Node{{ID: root8, Hash: []byte("root-of-00")}}}); err != nil {
			t.Fatalf("Add(root tile): %v", err)
		}
		if err := ts.Add(Tile{
			ID:     root8,
			Leaves: []Node{{ID: tileID, Hash: []byte("root-of-0000")}},
		}); err != nil {
			t.Fatalf("Add(tile 0x00): %v", err)
		}
		if err := ts.Add(Tile{
			ID: tileID,
			Leaves: []Node{
				{ID: id00, Hash: []byte("hash_0000")},
				{ID: id70, Hash: []byte("hash_0070")},
			},
		}); err != nil {
			t.Fatalf("Add(tile 0x00): %v", err)
		}
		return ts
	}

	t.Run("untampered-update-succeeds", func(t *testing.T) {
		ts := newSet()
		// Compute the genuine root hash and plant it as the parent-tile leaf.
		genuine, err := Tile{
			ID:     tileID,
			Leaves: ts.tiles[tileID],
		}.rootHash(l, ts.h)
		if err != nil {
			t.Fatalf("rootHash: %v", err)
		}
		ts.hashes[tileID] = genuine

		m := NewTileSetMutation(ts)
		m.Set(id0000, []byte("new_000000"))
		if _, err := m.Build(); err != nil {
			t.Fatalf("Build: %v", err)
		}
	})

	t.Run("tampered-persisted-leaf-rejected", func(t *testing.T) {
		ts := newSet()
		genuine, err := Tile{
			ID:     tileID,
			Leaves: ts.tiles[tileID],
		}.rootHash(l, ts.h)
		if err != nil {
			t.Fatalf("rootHash: %v", err)
		}
		ts.hashes[tileID] = genuine

		// Tamper with a persisted node hash; the recorded root stays genuine.
		ts.tiles[tileID][0].Hash = []byte("tampered")

		m := NewTileSetMutation(ts)
		m.Set(id0070, []byte("new_000070"))
		if _, err := m.Build(); err == nil ||
			!strings.Contains(err.Error(), "persisted root hash") {
			t.Fatalf("Build: got %v, want persisted root hash mismatch", err)
		}
	})

	t.Run("misfiled-node-rejected", func(t *testing.T) {
		ts := newSet()
		genuine, err := Tile{
			ID:     tileID,
			Leaves: ts.tiles[tileID],
		}.rootHash(l, ts.h)
		if err != nil {
			t.Fatalf("rootHash: %v", err)
		}
		ts.hashes[tileID] = genuine

		// Replace a persisted node with one from another subtree. The first and
		// last IDs alone would not catch this when it sits in the middle.
		other := node.NewID("\x00\x01\x01", 24)
		ts.tiles[tileID] = []Node{
			{ID: id00, Hash: []byte("hash_0000")},
			{ID: other, Hash: []byte("hash_0101")},
			{ID: id70, Hash: []byte("hash_0070")},
		}

		m := NewTileSetMutation(ts)
		m.Set(id0000, []byte("new_000000"))
		if _, err := m.Build(); err == nil ||
			!strings.Contains(err.Error(), "tile leaves") {
			t.Fatalf("Build: got %v, want structural tile validation error", err)
		}
	})

	t.Run("missing-recorded-root-rejected", func(t *testing.T) {
		ts := newSet()
		delete(ts.hashes, tileID)

		m := NewTileSetMutation(ts)
		m.Set(id0000, []byte("new_000000"))
		if _, err := m.Build(); err == nil ||
			!strings.Contains(err.Error(), "no persisted root hash") {
			t.Fatalf("Build: got %v, want missing root hash error", err)
		}
	})
}
