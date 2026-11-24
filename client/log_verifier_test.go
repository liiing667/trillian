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
	"context"
	"strings"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/rfc6962"
	inmemory "github.com/transparency-dev/merkle/testonly"
	"google.golang.org/grpc"
)

func TestVerifyRootErrors(t *testing.T) {
	logRoot, err := (&types.LogRootV1{}).MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to create test signature: %v", err)
	}
	signedRoot := &trillian.SignedLogRoot{LogRoot: logRoot}

	// Test execution
	tests := []struct {
		desc    string
		trusted *types.LogRootV1
		newRoot *trillian.SignedLogRoot
	}{
		{desc: "newRootNil", trusted: &types.LogRootV1{}, newRoot: nil},
		{desc: "trustedNil", trusted: nil, newRoot: signedRoot},
	}
	for _, test := range tests {
		logVerifier := NewLogVerifier(rfc6962.DefaultHasher)

		// This also makes sure that no nil pointer dereference errors occur (as this would cause a panic).
		if _, err := logVerifier.VerifyRoot(test.trusted, test.newRoot, nil); err == nil {
			t.Errorf("%v: VerifyRoot() error expected, but got nil", test.desc)
		}
	}
}

func TestVerifyInclusionByHashErrors(t *testing.T) {
	tests := []struct {
		desc    string
		trusted *types.LogRootV1
		proof   *trillian.Proof
	}{
		{desc: "trustedNil", trusted: nil, proof: &trillian.Proof{}},
		{desc: "proofNil", trusted: &types.LogRootV1{}, proof: nil},
	}
	for _, test := range tests {

		logVerifier := NewLogVerifier(nil)
		err := logVerifier.VerifyInclusionByHash(test.trusted, nil, test.proof)
		if err == nil {
			t.Errorf("%v: VerifyInclusionByHash() error expected, but got nil", test.desc)
		}
	}
}

func TestVerifyRootBoundary(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := inmemory.New(hasher)
	tree.AppendData([]byte("a"), []byte("b"), []byte("c"), []byte("d"))

	root := func(size uint64, hash []byte) *trillian.SignedLogRoot {
		b, err := (&types.LogRootV1{TreeSize: size, RootHash: hash}).MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(): %v", err)
		}
		return &trillian.SignedLogRoot{LogRoot: b}
	}

	tests := []struct {
		name      string
		trusted   *types.LogRootV1
		candidate *trillian.SignedLogRoot
		proof     [][]byte
		wantErr   bool
		wantText  []string
	}{
		{
			name:      "emptyFirstRootHash",
			trusted:   &types.LogRootV1{},
			candidate: root(1, nil),
			wantErr:   true,
			wantText:  []string{"trusted root generation 0/", "candidate root generation 1/", "root hash is empty"},
		},
		{
			name:      "shortFirstRootHash",
			trusted:   &types.LogRootV1{},
			candidate: root(1, []byte("short")),
			wantErr:   true,
			wantText:  []string{"trusted root generation 0/", "candidate root generation 1/", "root hash length"},
		},
		{
			name:      "emptyTreeHashAtNonZeroSize",
			trusted:   &types.LogRootV1{},
			candidate: root(1, hasher.EmptyRoot()),
			wantErr:   true,
			wantText:  []string{"candidate root generation 1/", "empty-tree hash"},
		},
		{
			name:      "allZeroHashAtNonZeroSize",
			trusted:   &types.LogRootV1{},
			candidate: root(1, make([]byte, hasher.Size())),
			wantErr:   true,
			wantText:  []string{"candidate root generation 1/", "all zero"},
		},
		{
			name:      "validFirstRoot",
			trusted:   &types.LogRootV1{},
			candidate: root(1, tree.HashAt(1)),
		},
		{
			name:      "emptyRootCompatibility",
			trusted:   &types.LogRootV1{},
			candidate: root(0, []byte("root")),
		},
		{
			name:      "shrinkingTree",
			trusted:   &types.LogRootV1{TreeSize: 3, RootHash: tree.HashAt(3)},
			candidate: root(2, tree.HashAt(2)),
			wantErr:   true,
			wantText:  []string{"tree size decreased from 3 to 2", "trusted root generation 3/", "candidate root generation 2/"},
		},
		{
			name:      "equalSizeDifferentHash",
			trusted:   &types.LogRootV1{TreeSize: 3, RootHash: tree.HashAt(3)},
			candidate: root(3, tree.HashAt(2)),
			wantErr:   true,
			wantText:  []string{"trusted root generation 3/", "candidate root generation 3/"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := NewLogVerifier(hasher)
			_, err := verifier.VerifyRoot(test.trusted, test.candidate, test.proof)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("VerifyRoot() error = %v, wantErr %v", err, test.wantErr)
			}
			for _, want := range test.wantText {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("VerifyRoot() error = %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestVerifyRootConsistency(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := inmemory.New(hasher)
	tree.AppendData([]byte("a"), []byte("b"), []byte("c"), []byte("d"))

	consistency, err := tree.ConsistencyProof(2, 4)
	if err != nil {
		t.Fatalf("ConsistencyProof(2, 4): %v", err)
	}
	candidate, err := (&types.LogRootV1{TreeSize: 4, RootHash: tree.HashAt(4)}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	trusted := &types.LogRootV1{TreeSize: 2, RootHash: tree.HashAt(2)}

	verifier := NewLogVerifier(hasher)
	if _, err := verifier.VerifyRoot(trusted, &trillian.SignedLogRoot{LogRoot: candidate}, consistency); err != nil {
		t.Fatalf("VerifyRoot() with valid consistency proof: %v", err)
	}

	badProof, err := tree.ConsistencyProof(1, 4)
	if err != nil {
		t.Fatalf("ConsistencyProof(1, 4): %v", err)
	}
	if _, err := verifier.VerifyRoot(trusted, &trillian.SignedLogRoot{LogRoot: candidate}, badProof); err == nil {
		t.Fatal("VerifyRoot() accepted a consistency proof for a different trusted size")
	}
}

func TestVerifyInclusionByHashBinding(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := inmemory.New(hasher)
	tree.AppendData([]byte("a"), []byte("b"), []byte("c"), []byte("d"))

	hashes, err := tree.InclusionProof(1, 3)
	if err != nil {
		t.Fatalf("InclusionProof(1, 3): %v", err)
	}
	leafHash := tree.LeafHash(1)
	trusted3 := &types.LogRootV1{TreeSize: 3, RootHash: tree.HashAt(3)}
	verifier := NewLogVerifier(hasher)

	if err := verifier.VerifyInclusionByHash(trusted3, leafHash, &trillian.Proof{LeafIndex: 1, Hashes: hashes}); err != nil {
		t.Fatalf("VerifyInclusionByHash() with matching root: %v", err)
	}

	for _, test := range []struct {
		name    string
		trusted *types.LogRootV1
		index   int64
		hashes  [][]byte
	}{
		{name: "differentTreeSize", trusted: &types.LogRootV1{TreeSize: 4, RootHash: tree.HashAt(4)}, index: 1, hashes: hashes},
		{name: "smallerTreeSize", trusted: &types.LogRootV1{TreeSize: 2, RootHash: tree.HashAt(2)}, index: 1, hashes: hashes},
		{name: "indexOutsideTree", trusted: trusted3, index: 3, hashes: hashes},
		{name: "negativeIndex", trusted: trusted3, index: -1, hashes: hashes},
		{name: "emptyTrustedRoot", trusted: &types.LogRootV1{}, index: 0, hashes: hashes},
		{name: "shortTrustedHash", trusted: &types.LogRootV1{TreeSize: 3, RootHash: []byte("short")}, index: 1, hashes: hashes},
		{name: "shortProofHash", trusted: trusted3, index: 1, hashes: [][]byte{[]byte("short")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := verifier.VerifyInclusionByHash(test.trusted, leafHash, &trillian.Proof{LeafIndex: test.index, Hashes: test.hashes}); err == nil {
				t.Error("VerifyInclusionByHash() accepted a proof not bound to the trusted root")
			}
		})
	}
}

// sequenceLogClient is a minimal TrillianLogClient that returns a fixed sequence
// of latest-root responses.
type sequenceLogClient struct {
	trillian.TrillianLogClient
	responses []*trillian.GetLatestSignedLogRootResponse
}

func (c *sequenceLogClient) GetLatestSignedLogRoot(context.Context, *trillian.GetLatestSignedLogRootRequest, ...grpc.CallOption) (*trillian.GetLatestSignedLogRootResponse, error) {
	resp := c.responses[0]
	c.responses = c.responses[1:]
	return resp, nil
}

func TestUpdateRootPreservesTrustedGenerationOnFailure(t *testing.T) {
	hasher := rfc6962.DefaultHasher
	tree := inmemory.New(hasher)
	tree.AppendData([]byte("a"), []byte("b"), []byte("c"), []byte("d"))

	signedRoot := func(size uint64, hash []byte, timestamp uint64) *trillian.GetLatestSignedLogRootResponse {
		b, err := (&types.LogRootV1{TreeSize: size, RootHash: hash, TimestampNanos: timestamp}).MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(): %v", err)
		}
		return &trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: b}}
	}
	consistency, err := tree.ConsistencyProof(2, 4)
	if err != nil {
		t.Fatalf("ConsistencyProof(2, 4): %v", err)
	}
	validUpdate := signedRoot(4, tree.HashAt(4), 3)
	validUpdate.Proof = &trillian.Proof{Hashes: consistency}

	client := New(1, &sequenceLogClient{responses: []*trillian.GetLatestSignedLogRootResponse{
		signedRoot(1, tree.HashAt(1), 2), // Shrinking root must be rejected.
		validUpdate,
		signedRoot(0, []byte("root"), 4), // Empty root must not revive an old generation.
	}}, NewLogVerifier(hasher), types.LogRootV1{TreeSize: 2, RootHash: tree.HashAt(2), TimestampNanos: 1})

	if _, err := client.UpdateRoot(context.Background()); err == nil {
		t.Fatal("UpdateRoot() accepted a shrinking root")
	}
	if got := client.GetRoot(); got.TreeSize != 2 || string(got.RootHash) != string(tree.HashAt(2)) {
		t.Fatalf("failed update advanced trusted root to %d/%x", got.TreeSize, got.RootHash)
	}

	if _, err := client.UpdateRoot(context.Background()); err != nil {
		t.Fatalf("UpdateRoot() with valid consistency proof: %v", err)
	}
	if got := client.GetRoot(); got.TreeSize != 4 || string(got.RootHash) != string(tree.HashAt(4)) {
		t.Fatalf("valid update stored %d/%x, want 4/%x", got.TreeSize, got.RootHash, tree.HashAt(4))
	}

	if _, err := client.UpdateRoot(context.Background()); err == nil {
		t.Fatal("UpdateRoot() accepted a transition back to an empty tree")
	}
	if got := client.GetRoot(); got.TreeSize != 4 || string(got.RootHash) != string(tree.HashAt(4)) {
		t.Fatalf("failed empty update advanced trusted root to %d/%x", got.TreeSize, got.RootHash)
	}
}
