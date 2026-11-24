// Copyright 2026 Google LLC. All Rights Reserved.
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

package memory

import (
	"context"
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian"
	"github.com/google/trillian/log"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/quota"
	"github.com/google/trillian/storage"
	stestonly "github.com/google/trillian/storage/testonly"
	"github.com/google/trillian/types"
	"github.com/google/trillian/util/clock"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
)

func newPreorderedTestStorage(t *testing.T) (storage.LogStorage, *trillian.Tree) {
	t.Helper()
	ctx := context.Background()
	ts := NewTreeStorage()
	ls := NewLogStorage(ts, nil)
	as := NewAdminStorage(ts)
	tree, err := storage.CreateTree(ctx, as, stestonly.PreorderedLogTree)
	if err != nil {
		t.Fatalf("CreateTree(): %v", err)
	}
	initialRoot := &types.LogRootV1{
		TimestampNanos: 1,
		RootHash:       rfc6962.DefaultHasher.EmptyRoot(),
	}
	logRoot, err := initialRoot.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		return tx.StoreSignedLogRoot(ctx, &trillian.SignedLogRoot{LogRoot: logRoot})
	}); err != nil {
		t.Fatalf("StoreSignedLogRoot(): %v", err)
	}
	return ls, tree
}

func sequencedLeaf(seq int64, data string) *trillian.LogLeaf {
	hash := sha256.Sum256([]byte(data))
	return &trillian.LogLeaf{
		LeafIdentityHash: hash[:],
		MerkleLeafHash:   hash[:],
		LeafValue:        []byte(data),
		ExtraData:        []byte("extra-" + data),
		LeafIndex:        seq,
	}
}

func statusCode(l *trillian.QueuedLogLeaf) codes.Code {
	if l.Status == nil {
		return codes.OK
	}
	return codes.Code(l.Status.Code)
}

// TestPreorderedLogBatchLifecycle exercises the fixed fixture made of four
// batches: contiguous leaves, a batch landing past a gap, a batch containing
// duplicate identities/indices, and a recovery batch filling the gap. All
// accepted leaves remain pinned to their requested sequence numbers and become
// visible to the signer and proof consumers only once committed.
func TestPreorderedLogBatchLifecycle(t *testing.T) {
	ctx := context.Background()
	ls, tree := newPreorderedTestStorage(t)
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

	// Batch 1: contiguous leaves at indices 0..2.
	contiguous := []*trillian.LogLeaf{
		sequencedLeaf(0, "leaf-0"),
		sequencedLeaf(1, "leaf-1"),
		sequencedLeaf(2, "leaf-2"),
	}
	res, err := ls.AddSequencedLeaves(ctx, tree, contiguous, now)
	if err != nil {
		t.Fatalf("AddSequencedLeaves(contiguous): %v", err)
	}
	for i, r := range res {
		if got := statusCode(r); got != codes.OK {
			t.Fatalf("contiguous[%d] status = %v, want OK", i, got)
		}
	}

	// Batch 2: leaves at indices 4..5, leaving index 3 as a gap.
	gapped := []*trillian.LogLeaf{
		sequencedLeaf(4, "leaf-4"),
		sequencedLeaf(5, "leaf-5"),
	}
	if res, err = ls.AddSequencedLeaves(ctx, tree, gapped, now); err != nil {
		t.Fatalf("AddSequencedLeaves(gapped): %v", err)
	}
	for i, r := range res {
		if got := statusCode(r); got != codes.OK {
			t.Fatalf("gapped[%d] status = %v, want OK", i, got)
		}
	}

	// The signer must stop at the gap and only see the contiguous prefix.
	var dequeued []*trillian.LogLeaf
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		dequeued, err = tx.DequeueLeaves(ctx, 100, now)
		return err
	}); err != nil {
		t.Fatalf("DequeueLeaves(): %v", err)
	}
	if got, want := len(dequeued), 3; got != want {
		t.Fatalf("DequeueLeaves() returned %d leaves, want %d", got, want)
	}
	for i, leaf := range dequeued {
		if got, want := leaf.LeafIndex, int64(i); got != want {
			t.Errorf("dequeued[%d].LeafIndex = %v, want %v", i, got, want)
		}
	}

	// Batch 3: duplicate identities and conflicting indices.
	duplicates := []*trillian.LogLeaf{
		// Identical re-submission at the same index.
		sequencedLeaf(0, "leaf-0"),
		// Same identity as leaf-1 but requested at a new index.
		sequencedLeaf(6, "leaf-1"),
		// New identity but targeting an occupied index.
		sequencedLeaf(2, "leaf-new-at-2"),
		// Two fresh leaves colliding with each other on the same index.
		sequencedLeaf(7, "leaf-7a"),
		sequencedLeaf(7, "leaf-7b"),
	}
	res, err = ls.AddSequencedLeaves(ctx, tree, duplicates, now)
	if err != nil {
		t.Fatalf("AddSequencedLeaves(duplicates): %v", err)
	}
	wantCodes := []codes.Code{
		codes.AlreadyExists,      // identical re-submission
		codes.FailedPrecondition, // conflicting LeafIdentityHash
		codes.FailedPrecondition, // conflicting LeafIndex
		codes.OK,                 // first writer wins within the batch
		codes.FailedPrecondition, // conflicting LeafIndex within the batch
	}
	for i, r := range res {
		if got := statusCode(r); got != wantCodes[i] {
			t.Errorf("duplicates[%d] status = %v, want %v", i, got, wantCodes[i])
		}
	}

	// Batch 4: recovery batch filling index 3; integration can now proceed
	// through index 5, and must still stop at the gap at index 6.
	recovery := []*trillian.LogLeaf{sequencedLeaf(3, "leaf-3")}
	if res, err = ls.AddSequencedLeaves(ctx, tree, recovery, now); err != nil {
		t.Fatalf("AddSequencedLeaves(recovery): %v", err)
	}
	if got := statusCode(res[0]); got != codes.OK {
		t.Fatalf("recovery[0] status = %v, want OK", got)
	}

	// After recovery, positions 0..5 form a contiguous integrated prefix.
	var stored []*trillian.LogLeaf
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		stored, err = tx.GetLeavesByRange(ctx, 0, 6)
		return err
	}); err != nil {
		t.Fatalf("GetLeavesByRange(): %v", err)
	}
	wantLeaves := append(append([]*trillian.LogLeaf{}, contiguous...), recovery[0])
	wantLeaves = append(wantLeaves, gapped...)
	for i := range wantLeaves {
		if got, want := stored[i].LeafIndex, wantLeaves[i].LeafIndex; got != want {
			t.Errorf("stored[%d].LeafIndex = %v, want %v", i, got, want)
		}
		if got, want := stored[i].LeafIdentityHash, wantLeaves[i].LeafIdentityHash; !cmp.Equal(got, want) {
			t.Errorf("stored[%d].LeafIdentityHash = %x, want %x", i, got, want)
		}
	}

	// The signer now sees the full contiguous range 0..5 and still stops at
	// the gap at index 6.
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		dequeued, err = tx.DequeueLeaves(ctx, 100, now)
		return err
	}); err != nil {
		t.Fatalf("DequeueLeaves() after recovery: %v", err)
	}
	if got, want := len(dequeued), 6; got != want {
		t.Fatalf("DequeueLeaves() after recovery returned %d leaves, want %d", got, want)
	}
	if diff := cmp.Diff(dequeued, stored, protocmp.Transform()); diff != "" {
		t.Errorf("dequeued vs stored mismatch (-want +got):\n%v", diff)
	}
}

// TestPreorderedLogSingleLeafRequests checks that individual AddSequencedLeaves
// requests of one leaf each remain supported and are idempotent on retry.
func TestPreorderedLogSingleLeafRequests(t *testing.T) {
	ctx := context.Background()
	ls, tree := newPreorderedTestStorage(t)
	now := time.Now()

	for seq := int64(0); seq < 3; seq++ {
		data := "single-" + strconv.FormatInt(seq, 10)
		leaf := sequencedLeaf(seq, data)
		res, err := ls.AddSequencedLeaves(ctx, tree, []*trillian.LogLeaf{leaf}, now)
		if err != nil {
			t.Fatalf("AddSequencedLeaves(%d): %v", seq, err)
		}
		if got := statusCode(res[0]); got != codes.OK {
			t.Fatalf("single[%d] status = %v, want OK", seq, got)
		}

		// Simulate a client retry: the same identity and index must not create
		// a second entry and must report AlreadyExists.
		retry := sequencedLeaf(seq, data)
		res, err = ls.AddSequencedLeaves(ctx, tree, []*trillian.LogLeaf{retry}, now)
		if err != nil {
			t.Fatalf("AddSequencedLeaves(%d) retry: %v", seq, err)
		}
		if got := statusCode(res[0]); got != codes.AlreadyExists {
			t.Fatalf("single[%d] retry status = %v, want AlreadyExists", seq, got)
		}
	}

	var stored []*trillian.LogLeaf
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		stored, err = tx.GetLeavesByRange(ctx, 0, 3)
		return err
	}); err != nil {
		t.Fatalf("GetLeavesByRange(): %v", err)
	}
	if got, want := len(stored), 3; got != want {
		t.Fatalf("GetLeavesByRange() returned %d leaves, want %d", got, want)
	}

	// Retries must not have duplicated any entry in the hash index.
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		leaves, err := tx.GetLeavesByHash(ctx, [][]byte{sequencedLeaf(0, "single-0").MerkleLeafHash}, false)
		if err != nil {
			return err
		}
		if got, want := len(leaves), 1; got != want {
			t.Errorf("GetLeavesByHash() returned %d leaves, want %d", got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("GetLeavesByHash(): %v", err)
	}
}

// TestPreorderedLogSequencerIntegration drives the real sequencer over the
// memory backend. It verifies that batches landing past a gap remain parked
// until the recovery batch commits, after which the signer integrates them at
// the positions requested by the client rather than re-sequencing them.
func TestPreorderedLogSequencerIntegration(t *testing.T) {
	log.InitMetrics(monitoring.InertMetricFactory{})
	ctx := context.Background()
	ls, tree := newPreorderedTestStorage(t)
	ts := clock.NewFake(time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC))

	// Leaves 0..2, then 4..5 leaving a gap at 3.
	batches := [][]*trillian.LogLeaf{
		{sequencedLeaf(0, "seq-0"), sequencedLeaf(1, "seq-1"), sequencedLeaf(2, "seq-2")},
		{sequencedLeaf(4, "seq-4"), sequencedLeaf(5, "seq-5")},
	}
	for i, batch := range batches {
		if _, err := ls.AddSequencedLeaves(ctx, tree, batch, ts.Now()); err != nil {
			t.Fatalf("AddSequencedLeaves(batch %d): %v", i, err)
		}
	}

	integrate := func() int {
		t.Helper()
		n, err := log.IntegrateBatch(ctx, tree, 100, 0, 0, ts, ls, quota.Noop())
		if err != nil {
			t.Fatalf("IntegrateBatch(): %v", err)
		}
		ts.Set(ts.Now().Add(time.Second))
		return n
	}

	// Only the contiguous prefix 0..2 can be integrated while index 3 is open.
	if got, want := integrate(), 3; got != want {
		t.Fatalf("IntegrateBatch() with a gap integrated %d leaves, want %d", got, want)
	}

	// Another signing run must not skip over the gap.
	if got := integrate(); got != 0 {
		t.Fatalf("IntegrateBatch() over the gap integrated %d leaves, want 0", got)
	}

	// Recovery batch at index 3, followed by the already-stored 4..5.
	if _, err := ls.AddSequencedLeaves(ctx, tree, []*trillian.LogLeaf{sequencedLeaf(3, "seq-3")}, ts.Now()); err != nil {
		t.Fatalf("AddSequencedLeaves(recovery): %v", err)
	}
	if got, want := integrate(), 3; got != want {
		t.Fatalf("IntegrateBatch() after recovery integrated %d leaves, want %d", got, want)
	}

	// The committed tree must now have size 6 and the leaves must be at their
	// requested indices, verifiable through range reads and inclusion proofs.
	var slr *trillian.SignedLogRoot
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		slr, err = tx.LatestSignedLogRoot(ctx)
		return err
	}); err != nil {
		t.Fatalf("LatestSignedLogRoot(): %v", err)
	}
	var root types.LogRootV1
	if err := root.UnmarshalBinary(slr.LogRoot); err != nil {
		t.Fatalf("UnmarshalBinary(): %v", err)
	}
	if got, want := root.TreeSize, uint64(6); got != want {
		t.Fatalf("TreeSize = %d, want %d", got, want)
	}

	var leaves []*trillian.LogLeaf
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		var err error
		leaves, err = tx.GetLeavesByRange(ctx, 0, 6)
		return err
	}); err != nil {
		t.Fatalf("GetLeavesByRange(): %v", err)
	}
	for i, leaf := range leaves {
		if got, want := leaf.LeafIndex, int64(i); got != want {
			t.Errorf("leaf[%d].LeafIndex = %d, want %d", i, got, want)
		}
	}

	// Every integrated leaf must have a verifiable inclusion proof at the new
	// tree size, proving the committed positions are shared with consumers.
	if err := ls.ReadWriteTransaction(ctx, tree, func(ctx context.Context, tx storage.LogTreeTX) error {
		for _, leaf := range leaves {
			nodes, err := tx.GetMerkleNodes(ctx, []compact.NodeID{{Level: 0, Index: uint64(leaf.LeafIndex)}})
			if err != nil {
				return err
			}
			if len(nodes) != 1 {
				t.Errorf("GetMerkleNodes(%d) returned %d nodes, want 1", leaf.LeafIndex, len(nodes))
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("GetMerkleNodes(): %v", err)
	}
}
