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
	"sort"
	"strings"

	"github.com/google/trillian/merkle/smt/node"
)

// Node represents a sparse Merkle tree node.
type Node struct {
	ID   node.ID
	Hash []byte
}

// NodesRow contains nodes at the same tree level sorted by ID from left to
// right. The IDs of the nodes are unique.
//
// TODO(pavelkalinnikov): Hide nodes so that only this package can modify them.
type NodesRow []Node

// NewNodesRow creates a NodesRow from the given list of nodes. The nodes are
// reordered in-place if not already sorted.
func NewNodesRow(nodes []Node) (NodesRow, error) {
	if len(nodes) == 0 {
		return nodes, nil
	}
	if err := Prepare(nodes, nodes[0].ID.BitLen()); err != nil {
		return nil, err
	}
	return nodes, nil
}

// validate verifies all the Tile invariants for this row against the given
// tile root: every node is strictly below the root and shares its prefix, all
// the nodes are at the same depth, the row is ordered by ID from left to
// right, and node IDs are unique. An empty row is always valid.
func (n NodesRow) validate(root node.ID) error {
	if len(n) == 0 {
		return nil
	}
	rootLen := root.BitLen()
	depth := n[0].ID.BitLen()
	if depth <= rootLen {
		return fmt.Errorf("node depth %d is not below the tile root at depth %d", depth, rootLen)
	}
	for i, nd := range n {
		if d := nd.ID.BitLen(); d != depth {
			return fmt.Errorf("node #%d: invalid depth %d, want %d", i, d, depth)
		}
		if nd.ID.Prefix(rootLen) != root {
			return fmt.Errorf("node #%d: %v is not in the tile subtree %v", i, nd.ID, root)
		}
		if i > 0 {
			if c := compareHorizontal(n[i-1].ID, nd.ID); c > 0 {
				return fmt.Errorf("node #%d: row is not sorted by ID", i)
			} else if c == 0 {
				return fmt.Errorf("duplicate ID: %v", nd.ID)
			}
		}
	}
	return nil
}

// clone returns a copy of this row which does not share the backing slice
// with the original. An empty row remains empty.
func (n NodesRow) clone() NodesRow {
	if len(n) == 0 {
		return nil
	}
	res := make(NodesRow, len(n))
	copy(res, n)
	return res
}

// Prepare sorts the nodes slice for it to be usable by HStar3 algorithm and
// the sparse Merkle tree Writer. It also verifies that the nodes are placed at
// the required depth, and there are no duplicate IDs.
//
// TODO(pavelkalinnikov): Make this algorithm independent of Node type.
func Prepare(nodes []Node, depth uint) error {
	for i := range nodes {
		if d, want := nodes[i].ID.BitLen(), depth; d != want {
			return fmt.Errorf("node #%d: invalid depth %d, want %d", i, d, want)
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		return compareHorizontal(nodes[i].ID, nodes[j].ID) < 0
	})
	for i, last := 0, len(nodes)-1; i < last; i++ {
		if id := nodes[i].ID; id == nodes[i+1].ID {
			return fmt.Errorf("duplicate ID: %v", id)
		}
	}
	return nil
}

// compareHorizontal compares relative position of two node IDs at the same
// tree level. Returns -1 if the first node is to the left from the second one,
// 1 if the first node is to the right, and 0 if IDs are the same. The result
// is undefined if nodes are not at the same level.
func compareHorizontal(a, b node.ID) int {
	if res := strings.Compare(a.FullBytes(), b.FullBytes()); res != 0 {
		return res
	}
	aLast, _ := a.LastByte()
	bLast, _ := b.LastByte()
	if aLast == bLast {
		return 0
	} else if aLast < bLast {
		return -1
	}
	return 1
}
