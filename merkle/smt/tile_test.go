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

	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/merkle/smt/node"
)

func TestTileMerge(t *testing.T) {
	ids := []node.ID{
		node.NewID("\xAB\x00", 15),
		node.NewID("\xAB\x10", 15),
		node.NewID("\xAB\x20", 15),
		node.NewID("\xAB\x30", 15),
		node.NewID("\xAB\x40", 15),
		node.NewID("\xAC\x00", 15), // In another tile.
	}
	id := ids[0].Prefix(8)
	n := func(idIndex int, hash string) Node {
		return Node{ID: ids[idIndex], Hash: []byte(hash)}
	}

	for _, tc := range []struct {
		desc    string
		was     NodesRow
		upd     NodesRow
		want    NodesRow
		wantErr string
	}{
		{desc: "empty", want: nil},
		{desc: "no-updates", was: []Node{n(3, "h")}, want: []Node{n(3, "h")}},
		{desc: "add-to-empty", upd: []Node{n(0, "h")}, want: []Node{n(0, "h")}},
		{
			desc: "override-one",
			was:  []Node{n(0, "old")},
			upd:  []Node{n(0, "new")},
			want: []Node{n(0, "new")},
		},
		{
			desc: "add-multiple",
			was:  []Node{n(0, "old0"), n(3, "old3")},
			upd:  []Node{n(1, "new1"), n(2, "new2"), n(4, "new4")},
			want: []Node{n(0, "old0"), n(1, "new1"), n(2, "new2"), n(3, "old3"), n(4, "new4")},
		},
		{
			desc: "override-some",
			was:  []Node{n(0, "old0"), n(1, "old1"), n(2, "old2"), n(3, "old3")},
			upd:  []Node{n(1, "new1"), n(2, "new2")},
			want: []Node{n(0, "old0"), n(1, "new1"), n(2, "new2"), n(3, "old3")},
		},
		{
			desc: "override-and-add",
			was:  []Node{n(0, "old0"), n(1, "old1"), n(3, "old3"), n(4, "old4")},
			upd:  []Node{n(1, "new1"), n(2, "new2")},
			want: []Node{n(0, "old0"), n(1, "new1"), n(2, "new2"), n(3, "old3"), n(4, "old4")},
		},
		{
			desc:    "wrong-depth",
			was:     []Node{n(0, "old")},
			upd:     []Node{{ID: id}},
			wantErr: "updates: node depth 8 is not below the tile root",
		},
		{
			desc:    "wrong-tile",
			was:     []Node{n(0, "old")},
			upd:     []Node{n(5, "new")},
			wantErr: "updates: node #0:",
		},
		{
			desc:    "empty-wrong-depth",
			upd:     []Node{{ID: id}},
			wantErr: "updates: node depth 8 is not below the tile root",
		},
		{
			desc:    "empty-wrong-tile",
			upd:     []Node{n(5, "h")},
			wantErr: "updates: node #0:",
		},
		{
			desc:    "empty-unsorted",
			upd:     []Node{n(2, "h2"), n(1, "h1")},
			wantErr: "updates: node #1: row is not sorted",
		},
		{
			desc:    "empty-duplicate",
			upd:     []Node{n(1, "h1"), n(1, "h2")},
			wantErr: "updates: duplicate ID",
		},
		{
			desc:    "unsorted",
			was:     []Node{n(0, "old")},
			upd:     []Node{n(2, "h2"), n(1, "h1")},
			wantErr: "updates: node #1: row is not sorted",
		},
		{
			desc:    "duplicate",
			was:     []Node{n(0, "old")},
			upd:     []Node{n(1, "h1"), n(1, "h2")},
			wantErr: "updates: duplicate ID",
		},
		{
			desc:    "mixed-depth",
			was:     []Node{n(0, "old")},
			upd:     []Node{n(1, "h1"), {ID: node.NewID("\xAB\x01", 12)}},
			wantErr: "updates: node #1: invalid depth",
		},
		{
			desc: "cross-subtree-in-the-middle",
			was: []Node{
				n(0, "old0"),
				{ID: node.NewID("\xAC\x00", 15), Hash: []byte("other")},
				n(1, "old1"),
			},
			upd:     []Node{n(2, "new2")},
			wantErr: "tile leaves: node #1:",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			was := Tile{ID: id, Leaves: tc.was}
			got, err := was.Merge(tc.upd)
			if err != nil {
				if tc.wantErr == "" {
					t.Fatalf("Merge: want no error, returned: %v", err)
				}
				if want := tc.wantErr; !strings.HasPrefix(err.Error(), want) {
					t.Fatalf("Merge: got error: %v; want prefix %q", err, want)
				}
				return
			} else if want := tc.wantErr; want != "" {
				t.Fatalf("Merge: got no error; want prefix %q", want)
			}

			want := Tile{ID: id, Leaves: tc.want}
			if d := cmp.Diff(got, want, cmp.AllowUnexported(node.ID{})); d != "" {
				t.Errorf("Merge result mismatch:\n%s", d)
			}
		})
	}
}

func TestTileMergeCopiesInputs(t *testing.T) {
	id := node.NewID("\xAB", 8)
	leaf := func(suffix byte, hash string) Node {
		return Node{ID: node.NewID("\xAB"+string(suffix), 15), Hash: []byte(hash)}
	}
	sharesBacking := func(a, b NodesRow) bool {
		return len(a) > 0 && len(b) > 0 && &a[:1][0] == &b[:1][0]
	}

	t.Run("empty-updates-returns-copy", func(t *testing.T) {
		was := NodesRow{leaf(0x00, "h")}
		tile := Tile{ID: id, Leaves: was}
		got, err := tile.Merge(nil)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		if sharesBacking(got.Leaves, was) {
			t.Fatal("result Leaves share backing storage with the original tile")
		}
	})

	t.Run("empty-tile-copies-updates", func(t *testing.T) {
		upd := NodesRow{leaf(0x00, "h"), leaf(0x10, "h2")}
		got, err := Tile{ID: id}.Merge(upd)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		if sharesBacking(got.Leaves, upd) {
			t.Fatal("result Leaves share backing storage with updates")
		}
	})

	t.Run("merge-result-is-independent", func(t *testing.T) {
		was := NodesRow{leaf(0x00, "old"), leaf(0x20, "old2")}
		upd := NodesRow{leaf(0x10, "new")}
		got, err := Tile{ID: id, Leaves: was}.Merge(upd)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		if sharesBacking(got.Leaves, was) || sharesBacking(got.Leaves, upd) {
			t.Fatal("result Leaves share backing storage with an input")
		}
		// Mutating the inputs must not affect the returned tile.
		was[0].Hash = []byte("tampered")
		upd[0].Hash = []byte("tampered")
		if got.Leaves[0].Hash[0] != 'o' || got.Leaves[1].Hash[0] != 'n' {
			t.Fatal("mutating an input changed the merged tile")
		}
	})
}

func TestTileRootHash(t *testing.T) {
	l := NewLayout([]uint{8, 8})
	h := bindHasher(coniks.Default, 1)
	tileID := node.NewID("\x00", 8)
	leaves := []Node{
		{ID: node.NewID("\x00\x01", 16), Hash: []byte("hash_0001")},
		{ID: node.NewID("\x00\x70", 16), Hash: []byte("hash_0070")},
	}

	got, err := Tile{ID: tileID, Leaves: leaves}.rootHash(l, h)
	if err != nil {
		t.Fatalf("rootHash: %v", err)
	}

	// Compute the expected root independently with a bare HStar3 instance.
	leavesCopy := make([]Node, len(leaves))
	copy(leavesCopy, leaves)
	hs, err := NewHStar3(leavesCopy, h.mh.HashChildren, 16, 8)
	if err != nil {
		t.Fatalf("NewHStar3: %v", err)
	}
	upd, err := hs.Update(emptyHashes{h: h})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(upd) != 1 || upd[0].ID != tileID {
		t.Fatalf("expected a single root update at %v, got %v", tileID, upd)
	}
	if !reflect.DeepEqual(got, upd[0].Hash) {
		t.Fatalf("rootHash = %x, want %x", got, upd[0].Hash)
	}

	// An empty tile hashes as an empty subtree at its root.
	emptyRoot, err := Tile{ID: tileID}.rootHash(l, h)
	if err != nil {
		t.Fatalf("rootHash(empty): %v", err)
	}
	if !reflect.DeepEqual(emptyRoot, h.hashEmpty(tileID)) {
		t.Fatalf("empty rootHash = %x, want hashEmpty %x", emptyRoot, h.hashEmpty(tileID))
	}

	// Tampering with a leaf hash must change the recomputed root hash.
	tampered := make([]Node, len(leaves))
	copy(tampered, leaves)
	tampered[0].Hash = []byte("tampered")
	bad, err := Tile{ID: tileID, Leaves: tampered}.rootHash(l, h)
	if err != nil {
		t.Fatalf("rootHash(tampered): %v", err)
	}
	if reflect.DeepEqual(bad, got) {
		t.Fatal("tampered leaves produced the same root hash")
	}
}

func TestTileScan(t *testing.T) {
	lo := NewLayout([]uint{8, 24})
	h := bindHasher(coniks.Default, 1)

	ids := []node.ID{
		node.NewID("\x00", 8),
		node.NewID("\x02", 8),
		node.NewID("\xF0", 8),
		node.NewID("\x00\x01\x02\x03", 32),
	}
	prefixes := func(high, low uint, ids ...node.ID) []node.ID {
		ret := make([]node.ID, 0, int(high-low)*len(ids))
		for i := high; i > low; i-- {
			for _, id := range ids {
				ret = append(ret, id.Prefix(i))
			}
		}
		return ret
	}

	for _, tc := range []struct {
		id     node.ID
		leaves []Node
		visits []node.ID
	}{
		{leaves: nil, visits: []node.ID{}},
		{leaves: []Node{{ID: ids[0]}}, visits: prefixes(8, 0, ids[0])},
		{
			leaves: []Node{{ID: ids[0]}, {ID: ids[1]}},
			visits: append(prefixes(8, 6, ids[0], ids[1]), prefixes(6, 0, ids[0])...),
		},
		{
			leaves: []Node{{ID: ids[0]}, {ID: ids[2]}},
			visits: prefixes(8, 0, ids[0], ids[2]),
		},
		{id: ids[0], leaves: []Node{{ID: ids[3]}}, visits: prefixes(32, 8, ids[3])},
	} {
		t.Run("", func(t *testing.T) {
			tile := Tile{ID: tc.id, Leaves: tc.leaves}
			visits := make([]node.ID, 0, len(tc.visits))
			if err := tile.scan(lo, h, func(node Node) {
				visits = append(visits, node.ID)
			}); err != nil {
				t.Fatalf("scan: %v", err)
			}
			if got, want := visits, tc.visits; !reflect.DeepEqual(got, want) {
				t.Errorf("visits mismatch: got %d nodes, want %d other ones", len(got), len(want))
			}
		})
	}
}
