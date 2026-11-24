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

package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/testonly"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func fakeHandler(signer crypto.Signer, err error) ProtoHandler {
	return func(ctx context.Context, pb proto.Message) (crypto.Signer, error) {
		return signer, err
	}
}

func TestNewSigner(t *testing.T) {
	wantSigner, err := pem.UnmarshalPrivateKey(testonly.DemoPrivateKey, testonly.DemoPrivateKeyPass)
	if err != nil {
		t.Fatalf("Error unmarshaling test private key: %v", err)
	}

	ctx := context.Background()

	for _, test := range []struct {
		desc     string
		keyProto proto.Message
		handler  ProtoHandler
		wantErr  bool
	}{
		{
			desc:     "KeyProto with handler",
			keyProto: &emptypb.Empty{},
			handler:  fakeHandler(wantSigner, nil),
		},
		{
			desc:     "Invalid KeyProto with handler",
			keyProto: &emptypb.Empty{},
			handler:  fakeHandler(nil, errors.New("invalid KeyProto")),
			wantErr:  true,
		},
		{
			desc:     "KeyProto with no handler",
			keyProto: &emptypb.Empty{},
			wantErr:  true,
		},
		{
			desc:    "Nil KeyProto",
			wantErr: true,
		},
	} {
		if test.handler != nil {
			RegisterHandler(test.keyProto, test.handler)
		}

		gotSigner, err := NewSigner(ctx, test.keyProto)
		switch gotErr := err != nil; {
		case gotErr != test.wantErr:
			t.Errorf("%v: NewSigner() = (_, %q), want err? %v", test.desc, err, test.wantErr)
		case !gotErr && gotSigner != wantSigner:
			t.Errorf("%v: NewSigner() = (%#v, _), want (%#v, _)", test.desc, gotSigner, wantSigner)
		}

		if test.handler != nil {
			unregisterHandler(test.keyProto)
		}
	}
}

// TestRotationFailureRecovery exercises the fixed runtime scenario: a
// successful sign, a failed backend rotation that must not clobber the
// original handler, and a retry that succeeds.
func TestRotationFailureRecovery(t *testing.T) {
	ctx := context.Background()
	keyProto := &emptypb.Empty{}

	goodSigner, err := pem.UnmarshalPrivateKey(testonly.DemoPrivateKey, testonly.DemoPrivateKeyPass)
	if err != nil {
		t.Fatalf("Error unmarshaling test private key: %v", err)
	}

	// Capture the pre-test generation so it can be restored afterwards.
	saved := CurrentStore()
	defer RestoreStore(saved)

	digest := sha256.Sum256([]byte("test"))

	// 1. Successful sign with the original backend.
	RegisterHandler(keyProto, fakeHandler(goodSigner, nil))
	stable := CurrentStore()
	signer, err := NewSigner(ctx, keyProto)
	if err != nil {
		t.Fatalf("NewSigner() = (_, %q), want (_, nil)", err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign() with original backend = %q, want nil", err)
	}

	// 2. Failed rotation: the candidate backend is broken and must not
	// overwrite the original handler.
	badHandler := fakeHandler(nil, errors.New("broken backend"))
	gotStore, err := RotateHandler(ctx, keyProto, badHandler)
	if err == nil {
		t.Fatal("RotateHandler() with broken backend = nil error, want error")
	}
	if gotStore.Generation() != stable.Generation() {
		t.Errorf("Failed rotation changed store generation to %d, want it to stay at %d", gotStore.Generation(), stable.Generation())
	}
	// Both the previously created signer and new signers from the current
	// generation must still use the original backend.
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Errorf("Sign() with pre-rotation signer after failed rotation = %q, want nil", err)
	}
	signer2, err := NewSigner(ctx, keyProto)
	if err != nil {
		t.Fatalf("NewSigner() after failed rotation = (_, %q), want (_, nil)", err)
	}
	if _, err := signer2.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Errorf("Sign() with post-failure signer = %q, want nil", err)
	}

	// 3. Retry the rotation with a working backend.
	rotated, err := RotateHandler(ctx, keyProto, fakeHandler(goodSigner, nil))
	if err != nil {
		t.Fatalf("RotateHandler() retry = (_, %q), want (_, nil)", err)
	}
	if rotated.Generation() == stable.Generation() {
		t.Error("Successful rotation did not produce a new store generation")
	}
	if _, err := NewSigner(ctx, keyProto); err != nil {
		t.Errorf("NewSigner() after successful rotation = (_, %q), want (_, nil)", err)
	}

	// Recovery path: restoring the pre-rotation generation brings back the
	// exact handlers that were current then.
	RestoreStore(stable)
	if got := CurrentStore().Generation(); got != stable.Generation() {
		t.Errorf("CurrentStore().Generation() = %d after RestoreStore, want %d", got, stable.Generation())
	}
	if _, err := NewSigner(ctx, keyProto); err != nil {
		t.Errorf("NewSigner() after RestoreStore = (_, %q), want (_, nil)", err)
	}
}

// TestStoreGenerationsAreTrackable checks that concurrent rotations produce
// unique generations and that a stale publish is rejected.
func TestStoreGenerationsAreTrackable(t *testing.T) {
	keyProto := &emptypb.Empty{}
	saved := CurrentStore()
	defer RestoreStore(saved)

	const rotations = 16
	var wg sync.WaitGroup
	generations := make(chan uint64, rotations)
	for i := 0; i < rotations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			RegisterHandler(keyProto, fakeHandler(nil, fmt.Errorf("backend %d", i)))
			generations <- CurrentStore().Generation()
		}(i)
	}
	wg.Wait()
	close(generations)

	seen := make(map[uint64]bool)
	for g := range generations {
		if seen[g] {
			t.Errorf("Generation %d observed more than once", g)
		}
		seen[g] = true
	}

	// A publish based on a stale generation must be rejected.
	stale := CurrentStore()
	RegisterHandler(keyProto, fakeHandler(nil, nil))
	if err := PublishStore(stale, stale.WithHandler(keyProto, fakeHandler(nil, nil))); err == nil {
		t.Error("PublishStore() with stale generation = nil error, want error")
	}
}

// TestStoreSnapshotBinding checks that a captured store generation keeps
// selecting its own handlers even after the global registry moves on.
func TestStoreSnapshotBinding(t *testing.T) {
	ctx := context.Background()
	keyProto := &emptypb.Empty{}
	saved := CurrentStore()
	defer RestoreStore(saved)

	wantErr := errors.New("snapshot backend")
	RegisterHandler(keyProto, fakeHandler(nil, wantErr))
	snapshot := CurrentStore()

	// Rotate the global registry to a different backend.
	RegisterHandler(keyProto, fakeHandler(nil, nil))

	// The snapshot generation still binds to its own backend.
	if _, err := snapshot.NewSigner(ctx, keyProto); !errors.Is(err, wantErr) {
		t.Errorf("snapshot.NewSigner() = (_, %v), want (_, %v)", err, wantErr)
	}
	// While the current generation uses the new one.
	if _, err := NewSigner(ctx, keyProto); err != nil {
		t.Errorf("NewSigner() on current generation = (_, %q), want (_, nil)", err)
	}
}
