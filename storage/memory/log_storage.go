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

package memory

import (
	"container/list"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/btree"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/storage"
	"github.com/google/trillian/storage/cache"
	stree "github.com/google/trillian/storage/tree"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
)

const logIDLabel = "logid"

var (
	once            sync.Once
	queuedCounter   monitoring.Counter
	dequeuedCounter monitoring.Counter
)

func createMetrics(mf monitoring.MetricFactory) {
	queuedCounter = mf.NewCounter("mem_queued_leaves", "Number of leaves queued", logIDLabel)
	dequeuedCounter = mf.NewCounter("mem_dequeued_leaves", "Number of leaves dequeued", logIDLabel)
}

func labelForTX(t *logTreeTX) string {
	return strconv.FormatInt(t.treeID, 10)
}

// unseqKey formats a key for use in a tree's BTree store.
// The associated Item value will be a list of unsequenced entries.
func unseqKey(treeID int64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/unseq", treeID)}
}

// seqLeafKey formats a key for use in a tree's BTree store.
// The associated Item value will be the leaf at the given sequence number.
func seqLeafKey(treeID, seq int64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/seq/%020d", treeID, seq)}
}

// hashToSeqKey formats a key for use in a tree's BTree store.
// The associated Item value will be the sequence number for the leaf with
// the given hash.
func hashToSeqKey(treeID int64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/h2s", treeID)}
}

// identityHashKey formats a key for use in a tree's BTree store.
// The associated Item value will be a map from LeafIdentityHash to the
// sequence number (LeafIndex) of the leaf with that identity. It is used to
// detect conflicting identities when adding pre-ordered leaves.
func identityHashKey(treeID int64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/i2s", treeID)}
}

// sthKey formats a key for use in a tree's BTree store.
// The associated Item value will be the STH with the given timestamp.
func sthKey(treeID int64, timestamp uint64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/sth/%020d", treeID, timestamp)}
}

// revKey formats a key for use in a tree's BTree store. The associated Item
// value will be the revision number for the given timestamp.
func revKey(treeID int64, timestamp uint64) btree.Item {
	return &kv{k: fmt.Sprintf("/%d/rev/%020d", treeID, timestamp)}
}

type memoryLogStorage struct {
	*TreeStorage
	metricFactory monitoring.MetricFactory
}

// NewLogStorage creates an in-memory LogStorage instance.
func NewLogStorage(ts *TreeStorage, mf monitoring.MetricFactory) storage.LogStorage {
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	ret := &memoryLogStorage{
		TreeStorage:   ts,
		metricFactory: mf,
	}
	return ret
}

func (m *memoryLogStorage) CheckDatabaseAccessible(ctx context.Context) error {
	return nil
}

// GetActiveLogIDs returns the IDs of all logs that are currently in a state
// that requires sequencing (e.g. ACTIVE, DRAINING).
func (m *memoryLogStorage) GetActiveLogIDs(ctx context.Context) ([]int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ret []int64
	for id, tree := range m.trees {
		if tree.meta.GetDeleted() {
			continue
		}
		switch tree.meta.GetTreeType() {
		case trillian.TreeType_LOG, trillian.TreeType_PREORDERED_LOG:
			switch tree.meta.GetTreeState() {
			case trillian.TreeState_ACTIVE, trillian.TreeState_DRAINING:
				ret = append(ret, id)
			}
		}
	}

	return ret, nil
}

func (m *memoryLogStorage) beginInternal(ctx context.Context, tree *trillian.Tree, readonly bool) (*logTreeTX, error) {
	once.Do(func() {
		createMetrics(m.metricFactory)
	})

	stCache := cache.NewLogSubtreeCache(rfc6962.DefaultHasher)
	ttx, err := m.beginTreeTX(ctx, tree.TreeId, rfc6962.DefaultHasher.Size(), stCache, readonly)
	if err != nil {
		return nil, err
	}

	ltx := &logTreeTX{
		treeTX: ttx,
		ls:     m,
	}

	var rev int64
	ltx.slr, rev, err = ltx.fetchLatestRoot(ctx)
	if err == storage.ErrTreeNeedsInit {
		return ltx, err
	} else if err != nil {
		if err := ttx.Close(); err != nil {
			klog.Errorf("ttx.Close(): %v", err)
		}
		return nil, err
	}

	if err := ltx.root.UnmarshalBinary(ltx.slr.LogRoot); err != nil {
		if err := ttx.Close(); err != nil {
			klog.Errorf("ttx.Close(): %v", err)
		}
		return nil, err
	}

	ltx.writeRevision = rev + 1

	return ltx, nil
}

func (m *memoryLogStorage) ReadWriteTransaction(ctx context.Context, tree *trillian.Tree, f storage.LogTXFunc) error {
	tx, err := m.beginInternal(ctx, tree, false /* readonly */)
	if err != nil && err != storage.ErrTreeNeedsInit {
		return err
	}
	defer func() {
		if err := tx.Close(); err != nil {
			klog.Errorf("tx.Close(): %v", err)
		}
	}()
	if err := f(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AddSequencedLeaves stores the leaves at their requested LeafIndex positions
// in a single transaction. All the leaves become visible to subsequent
// transactions (including proof consumers and the signer) together, so a
// retried batch cannot land leaves out of order or at the wrong sequence
// number. Per-leaf statuses report gaps (missing positions are allowed),
// conflicting sequence numbers, and duplicate identities.
func (m *memoryLogStorage) AddSequencedLeaves(ctx context.Context, tree *trillian.Tree, leaves []*trillian.LogLeaf, timestamp time.Time) ([]*trillian.QueuedLogLeaf, error) {
	tx, err := m.beginInternal(ctx, tree, false /* readonly */)
	if tx != nil {
		// Ensure we don't leak the transaction. For example if we get an
		// ErrTreeNeedsInit from beginInternal() or if AddSequencedLeaves fails
		// below.
		defer func() {
			if err := tx.Close(); err != nil {
				klog.Errorf("tx.Close(): %v", err)
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	res, err := tx.AddSequencedLeaves(ctx, leaves, timestamp)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

func (m *memoryLogStorage) SnapshotForTree(ctx context.Context, tree *trillian.Tree) (storage.ReadOnlyLogTreeTX, error) {
	tx, err := m.beginInternal(ctx, tree, true /* readonly */)
	if err != nil {
		return nil, err
	}
	return tx, err
}

func (m *memoryLogStorage) QueueLeaves(ctx context.Context, tree *trillian.Tree, leaves []*trillian.LogLeaf, queueTimestamp time.Time) ([]*trillian.QueuedLogLeaf, error) {
	tx, err := m.beginInternal(ctx, tree, false /* readonly */)
	if tx != nil {
		// Ensure we don't leak the transaction. For example if we get an
		// ErrTreeNeedsInit from beginInternal() or if QueueLeaves fails
		// below.
		defer func() {
			if err := tx.Close(); err != nil {
				klog.Errorf("tx.Close(): %v", err)
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	existing, err := tx.QueueLeaves(ctx, leaves, queueTimestamp)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	ret := make([]*trillian.QueuedLogLeaf, len(leaves))
	for i, e := range existing {
		if e != nil {
			ret[i] = &trillian.QueuedLogLeaf{
				Leaf:   e,
				Status: status.Newf(codes.AlreadyExists, "leaf already exists: %v", e.LeafIdentityHash).Proto(),
			}
			continue
		}
		ret[i] = &trillian.QueuedLogLeaf{Leaf: leaves[i]}
	}
	return ret, nil
}

type logTreeTX struct {
	treeTX
	ls   *memoryLogStorage
	root types.LogRootV1
	slr  *trillian.SignedLogRoot
}

// GetMerkleNodes returns the requested nodes at (or below) the read revision.
func (t *logTreeTX) GetMerkleNodes(ctx context.Context, ids []compact.NodeID) ([]stree.Node, error) {
	rev := t.writeRevision - 1
	return t.subtreeCache.GetNodes(ids, t.getSubtreesAtRev(ctx, rev))
}

func (t *logTreeTX) DequeueLeaves(ctx context.Context, limit int, cutoffTime time.Time) ([]*trillian.LogLeaf, error) {
	if t.tree.meta.GetTreeType() == trillian.TreeType_PREORDERED_LOG {
		// Pre-ordered logs already carry their LeafIndex. Return the contiguous
		// head of the sequenced entries immediately following the current tree
		// size. A gap (an unoccupied position) blocks integration until the
		// missing batch is added, so stop at the first missing entry.
		leaves, err := t.getContiguousLeaves(int64(t.root.TreeSize), int64(limit))
		if err != nil {
			return nil, err
		}
		dequeuedCounter.Add(float64(len(leaves)), labelForTX(t))
		return leaves, nil
	}

	leaves := make([]*trillian.LogLeaf, 0, limit)

	q := t.tx.Get(unseqKey(t.treeID)).(*kv).v.(*list.List)
	e := q.Front()
	for i := 0; i < limit && e != nil; i++ {
		// TODO(al): consider cutoffTime
		leaves = append(leaves, e.Value.(*trillian.LogLeaf))
		e = e.Next()
	}

	dequeuedCounter.Add(float64(len(leaves)), labelForTX(t))
	return leaves, nil
}

// getContiguousLeaves returns up to count sequenced leaves with consecutive
// LeafIndex values starting at start. It stops at the first unoccupied
// position, meaning that leaves stored beyond a gap are not returned.
func (t *logTreeTX) getContiguousLeaves(start, count int64) ([]*trillian.LogLeaf, error) {
	if count <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid count %d, want > 0", count)
	}
	if start < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid start %d, want >= 0", start)
	}
	leaves := make([]*trillian.LogLeaf, 0, count)
	for i := int64(0); i < count; i++ {
		item := t.tx.Get(seqLeafKey(t.treeID, start+i))
		if item == nil {
			break
		}
		leaves = append(leaves, item.(*kv).v.(*trillian.LogLeaf))
	}
	return leaves, nil
}

func (t *logTreeTX) QueueLeaves(ctx context.Context, leaves []*trillian.LogLeaf, queueTimestamp time.Time) ([]*trillian.LogLeaf, error) {
	// Don't accept batches if any of the leaves are invalid.
	for _, leaf := range leaves {
		if len(leaf.LeafIdentityHash) != t.hashSizeBytes {
			return nil, fmt.Errorf("queued leaf must have a leaf ID hash of length %d", t.hashSizeBytes)
		}
		leaf.QueueTimestamp = timestamppb.New(queueTimestamp)
		if err := leaf.QueueTimestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("got invalid queue timestamp: %w", err)
		}
	}
	queuedCounter.Add(float64(len(leaves)), labelForTX(t))
	// No deduping in this storage!
	k := unseqKey(t.treeID)
	q := t.tx.Get(k).(*kv).v.(*list.List)
	for _, l := range leaves {
		q.PushBack(l)
	}
	return make([]*trillian.LogLeaf, len(leaves)), nil
}

// AddSequencedLeaves stores the leaves at the positions given by their
// LeafIndex fields.
//
// Batches do not have to continue the currently stored range: writing ahead of
// a gap (an out-of-order batch) is supported, and leaves simply remain
// un-integrated until the missing positions are filled. Conflicts within a
// batch or against previously committed entries are reported per leaf instead
// of failing the whole batch, mirroring the semantics of the SQL backends:
//   - OK: the leaf was stored.
//   - FailedPrecondition ("conflicting LeafIndex"): another leaf already
//     occupies the requested position.
//   - FailedPrecondition ("conflicting LeafIdentityHash"): a leaf with the
//     same identity hash is already stored at another position.
//
// All accepted leaves are written into this transaction, so they share one
// revision and become visible atomically on commit.
func (t *logTreeTX) AddSequencedLeaves(ctx context.Context, leaves []*trillian.LogLeaf, timestamp time.Time) ([]*trillian.QueuedLogLeaf, error) {
	res := make([]*trillian.QueuedLogLeaf, len(leaves))
	ok := status.New(codes.OK, "OK").Proto()

	identities := t.tx.Get(identityHashKey(t.treeID)).(*kv).v.(map[string]int64)

	// Track writes performed by this call so that a later leaf in the same
	// batch can conflict with an earlier one, even though nothing is visible to
	// other transactions before commit.
	pendingIndex := make(map[int64]bool, len(leaves))
	pendingIdentity := make(map[string]bool, len(leaves))

	for i, leaf := range leaves {
		res[i] = &trillian.QueuedLogLeaf{Status: ok}

		// This should fail on insert, but catch it early.
		if got, want := len(leaf.LeafIdentityHash), t.hashSizeBytes; got != want {
			return nil, status.Errorf(codes.FailedPrecondition, "leaves[%d] has incorrect hash size %d, want %d", i, got, want)
		}

		identity := string(leaf.LeafIdentityHash)

		// Detect duplicate identity first, mirroring the SQL backends: the
		// uniqueness of LeafIdentityHash is checked before the sequence number.
		seq, identityExists := identities[identity]
		if identityExists || pendingIdentity[identity] {
			if identityExists && seq == leaf.LeafIndex {
				// An identical re-submission of a previously committed leaf is
				// idempotent for the caller rather than a conflict.
				item := t.tx.Get(seqLeafKey(t.treeID, seq)).(*kv)
				res[i].Status = status.New(codes.AlreadyExists, "leaf already exists").Proto()
				res[i].Leaf = item.v.(*trillian.LogLeaf)
			} else {
				res[i].Status = status.New(codes.FailedPrecondition, "conflicting LeafIdentityHash").Proto()
			}
			continue
		}

		// Check for a conflicting sequence number, both against committed data
		// and against earlier leaves accepted in this batch.
		if existing := t.tx.Get(seqLeafKey(t.treeID, leaf.LeafIndex)); existing != nil {
			res[i].Status = status.New(codes.FailedPrecondition, "conflicting LeafIndex").Proto()
			res[i].Leaf = existing.(*kv).v.(*trillian.LogLeaf)
			continue
		}
		if pendingIndex[leaf.LeafIndex] {
			res[i].Status = status.New(codes.FailedPrecondition, "conflicting LeafIndex").Proto()
			continue
		}

		stored := proto.Clone(leaf).(*trillian.LogLeaf)
		stored.QueueTimestamp = timestamppb.New(timestamp)
		// Sequenced entries are not integrated yet, but the backends persist an
		// explicit zero integration timestamp rather than leaving it unset.
		stored.IntegrateTimestamp = timestamppb.New(time.Unix(0, 0))

		k := seqLeafKey(t.treeID, stored.LeafIndex)
		k.(*kv).v = stored
		t.tx.ReplaceOrInsert(k)

		identities[identity] = stored.LeafIndex
		m := t.tx.Get(hashToSeqKey(t.treeID)).(*kv).v.(map[string][]int64)
		m[string(stored.MerkleLeafHash)] = append(m[string(stored.MerkleLeafHash)], stored.LeafIndex)

		pendingIndex[stored.LeafIndex] = true
		pendingIdentity[identity] = true
	}

	return res, nil
}

// getLeavesByRangeInternal implements range reads over the sequenced entries.
// For pre-ordered logs, entries stored beyond the current tree size are
// visible so that the signer can integrate them. The returned slice is a
// contiguous prefix of the requested range; reading stops at the first
// unoccupied position. A gap within the current tree is an error, whereas a
// gap past the tree size simply terminates the result.
func (t *logTreeTX) getLeavesByRangeInternal(start, count int64) ([]*trillian.LogLeaf, error) {
	if count <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid count %d, want > 0", count)
	}
	if start < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid start %d, want >= 0", start)
	}

	if t.tree.meta.GetTreeType() != trillian.TreeType_PREORDERED_LOG {
		treeSize := int64(t.root.TreeSize)
		if treeSize <= 0 {
			return nil, status.Errorf(codes.OutOfRange, "empty tree")
		} else if start >= treeSize {
			return nil, status.Errorf(codes.OutOfRange, "invalid start %d, want < TreeSize(%d)", start, treeSize)
		}
		// Ensure no entries queried/returned beyond the tree.
		if maxCount := treeSize - start; count > maxCount {
			count = maxCount
		}
	}

	ret := make([]*trillian.LogLeaf, 0, count)
	for wantIndex := start; wantIndex < start+count; wantIndex++ {
		item := t.tx.Get(seqLeafKey(t.treeID, wantIndex))
		if item == nil {
			// A missing position inside the current tree is always an error.
			// Past the tree size, both ordinary logs (whose range was already
			// clipped above) and pre-ordered logs simply have no more entries
			// to return, so reading stops at the first gap.
			if wantIndex < int64(t.root.TreeSize) {
				return nil, status.Errorf(codes.OutOfRange, "missing leaf at index %d", wantIndex)
			}
			break
		}
		ret = append(ret, item.(*kv).v.(*trillian.LogLeaf))
	}
	return ret, nil
}

func (t *logTreeTX) GetLeavesByRange(ctx context.Context, start, count int64) ([]*trillian.LogLeaf, error) {
	return t.getLeavesByRangeInternal(start, count)
}

func (t *logTreeTX) GetLeavesByHash(ctx context.Context, leafHashes [][]byte, orderBySequence bool) ([]*trillian.LogLeaf, error) {
	m := t.tx.Get(hashToSeqKey(t.treeID)).(*kv).v.(map[string][]int64)

	ret := make([]*trillian.LogLeaf, 0, len(leafHashes))
	for _, hash := range leafHashes {
		seq, ok := m[string(hash)]
		if !ok {
			continue
		}
		for _, s := range seq {
			l := t.tx.Get(seqLeafKey(t.treeID, s))
			if l == nil {
				continue
			}
			ret = append(ret, l.(*kv).v.(*trillian.LogLeaf))
		}
	}
	return ret, nil
}

func (t *logTreeTX) LatestSignedLogRoot(ctx context.Context) (*trillian.SignedLogRoot, error) {
	return t.slr, nil
}

// fetchLatestRoot reads the latest SignedLogRoot from the DB and returns it.
func (t *logTreeTX) fetchLatestRoot(ctx context.Context) (*trillian.SignedLogRoot, int64, error) {
	r := t.tx.Get(sthKey(t.treeID, t.tree.currentSTH))
	if r == nil {
		return nil, 0, storage.ErrTreeNeedsInit
	}
	sth := r.(*kv).v.(*trillian.SignedLogRoot)

	r = t.tx.Get(revKey(t.treeID, t.tree.currentSTH))
	if r == nil {
		return nil, 0, storage.ErrTreeNeedsInit
	}
	rev := r.(*kv).v.(int64)

	return sth, rev, nil
}

func (t *logTreeTX) StoreSignedLogRoot(ctx context.Context, slr *trillian.SignedLogRoot) error {
	var root types.LogRootV1
	if err := root.UnmarshalBinary(slr.LogRoot); err != nil {
		return err
	}
	k := sthKey(t.treeID, root.TimestampNanos)
	k.(*kv).v = slr
	t.tx.ReplaceOrInsert(k)

	k = revKey(t.treeID, root.TimestampNanos)
	k.(*kv).v = t.writeRevision
	t.tx.ReplaceOrInsert(k)

	// TODO(alcutter): this breaks the transactional model
	if root.TimestampNanos > t.tree.currentSTH {
		t.tree.currentSTH = root.TimestampNanos
	}
	return nil
}

func (t *logTreeTX) UpdateSequencedLeaves(ctx context.Context, leaves []*trillian.LogLeaf) error {
	countByMerkleHash := make(map[string]int)
	for _, leaf := range leaves {
		// This should fail on insert but catch it early
		if got, want := len(leaf.LeafIdentityHash), t.hashSizeBytes; got != want {
			return fmt.Errorf("sequenced leaf has incorrect hash size: got %v, want %v", got, want)
		}
		mh := string(leaf.MerkleLeafHash)
		countByMerkleHash[mh]++
		// insert sequenced leaf:
		k := seqLeafKey(t.treeID, leaf.LeafIndex)
		k.(*kv).v = leaf
		t.tx.ReplaceOrInsert(k)
		// update merkle-to-seq mapping:
		m := t.tx.Get(hashToSeqKey(t.treeID))
		l := m.(*kv).v.(map[string][]int64)[string(leaf.MerkleLeafHash)]
		l = append(l, leaf.LeafIndex)
		m.(*kv).v.(map[string][]int64)[string(leaf.MerkleLeafHash)] = l
	}

	q := t.tx.Get(unseqKey(t.treeID)).(*kv).v.(*list.List)
	toRemove := make([]*list.Element, 0, q.Len())
	for e := q.Front(); e != nil && len(countByMerkleHash) > 0; e = e.Next() {
		h := e.Value.(*trillian.LogLeaf).MerkleLeafHash
		mh := string(h)
		if countByMerkleHash[mh] > 0 {
			countByMerkleHash[mh]--
			toRemove = append(toRemove, e)
			if countByMerkleHash[mh] == 0 {
				delete(countByMerkleHash, mh)
			}
		}
	}
	for _, e := range toRemove {
		q.Remove(e)
	}

	if unknown := len(countByMerkleHash); unknown != 0 {
		return fmt.Errorf("attempted to update %d unknown leaves: %x", unknown, countByMerkleHash)
	}

	return nil
}
