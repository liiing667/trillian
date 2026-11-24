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

// Package keys provides access to public and private keys for signing and verification of signatures.
package keys

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"k8s.io/klog/v2"
)

// ProtoHandler uses the information in a protobuf message to obtain a crypto.Signer.
// For example, the protobuf message may contain a key or identify where a key can be found.
type ProtoHandler func(context.Context, proto.Message) (crypto.Signer, error)

// Store is an immutable snapshot of the ProtoHandler registry at a specific
// generation. Handler selection, signing-tree binding (NewSigner) and
// rotation-failure recovery all operate on a Store, so a failed backend
// rotation can never clobber the handlers that existing trees and signers
// rely on: the previous generation remains intact and can be restored.
//
// A Store is safe for concurrent use; its handler set is never modified
// after construction.
type Store struct {
	generation uint64
	handlers   map[protoreflect.FullName]ProtoHandler
}

// Generation returns the store's generation number. Every store derived or
// published during the process lifetime has a unique generation, so
// concurrent rotations can be told apart and traced.
func (s *Store) Generation() uint64 {
	return s.generation
}

// Handler returns the ProtoHandler registered in this store generation for
// the type of keyProto, and whether one was found.
func (s *Store) Handler(keyProto proto.Message) (ProtoHandler, bool) {
	if keyProto == nil {
		return nil, false
	}
	handler, ok := s.handlers[keyProto.ProtoReflect().Descriptor().FullName()]
	return handler, ok
}

// NewSigner uses the ProtoHandler registered in this store generation to
// convert a protobuf message into a crypto.Signer.
// If there is no ProtoHandler registered for this type of protobuf message,
// an error will be returned.
//
// Signers created from a Store remain bound to the backend selected by this
// generation and stay usable even if the global registry later moves on to a
// new generation.
func (s *Store) NewSigner(ctx context.Context, keyProto proto.Message) (crypto.Signer, error) {
	if keyProto == nil {
		return nil, fmt.Errorf("nil keyProto")
	}
	keyProtoType := keyProto.ProtoReflect().Descriptor().FullName()

	if handler, ok := s.handlers[keyProtoType]; ok {
		return handler(ctx, keyProto)
	}

	return nil, fmt.Errorf("no ProtoHandler registered for protobuf %q", keyProtoType)
}

// WithHandler derives a new immutable store generation from s in which
// handler processes protobuf messages of the same type as keyProto. The
// keyProto need only be an empty example of the type of protobuf message
// that the handler can process - only its type is examined.
//
// s is left unmodified, so it can be restored (see RestoreStore) if a
// rotation to the derived generation fails.
func (s *Store) WithHandler(keyProto proto.Message, handler ProtoHandler) *Store {
	keyProtoType := keyProto.ProtoReflect().Descriptor().FullName()

	derived := make(map[protoreflect.FullName]ProtoHandler, len(s.handlers)+1)
	for t, h := range s.handlers {
		derived[t] = h
	}
	derived[keyProtoType] = handler

	return &Store{
		generation: nextGeneration(),
		handlers:   derived,
	}
}

// WithoutHandler derives a new immutable store generation from s with no
// handler registered for the type of keyProto. s is left unmodified.
func (s *Store) WithoutHandler(keyProto proto.Message) *Store {
	keyProtoType := keyProto.ProtoReflect().Descriptor().FullName()

	derived := make(map[protoreflect.FullName]ProtoHandler, len(s.handlers))
	for t, h := range s.handlers {
		if t != keyProtoType {
			derived[t] = h
		}
	}

	return &Store{
		generation: nextGeneration(),
		handlers:   derived,
	}
}

var (
	// generationCounter hands out unique, monotonically increasing generation
	// numbers so that every store generation is individually trackable.
	generationCounter atomic.Uint64

	// storeMu guards currentStore. The Store values themselves are immutable.
	storeMu      sync.Mutex
	currentStore = &Store{handlers: make(map[protoreflect.FullName]ProtoHandler)}
)

func nextGeneration() uint64 {
	return generationCounter.Add(1)
}

// CurrentStore returns the registry's current immutable store generation.
// The returned Store can be retained and used to bind signing trees to a
// stable set of backends, or restored later to recover from a failed
// rotation.
func CurrentStore() *Store {
	storeMu.Lock()
	defer storeMu.Unlock()
	return currentStore
}

// PublishStore atomically replaces the current store generation with next,
// provided the current generation is still expected. If another rotation has
// been published in the meantime, an error identifying both generations is
// returned and the registry is left untouched; the caller can re-derive its
// candidate from the new CurrentStore() and retry.
func PublishStore(expected, next *Store) error {
	storeMu.Lock()
	defer storeMu.Unlock()
	if currentStore != expected {
		return fmt.Errorf("concurrent rotation: current store generation is %d, want %d (candidate generation %d not published)",
			currentStore.Generation(), expected.Generation(), next.Generation())
	}
	currentStore = next
	return nil
}

// RestoreStore makes a previously captured store generation current again,
// e.g. to recover from a failed backend rotation that was already published.
// Because generations are immutable, the handlers and any signers created
// from the restored generation are exactly as they were when it was current.
// It returns the restored store.
func RestoreStore(prev *Store) *Store {
	storeMu.Lock()
	defer storeMu.Unlock()
	klog.Warningf("Restoring ProtoHandler store generation %d (was %d)", prev.Generation(), currentStore.Generation())
	currentStore = prev
	return prev
}

// RegisterHandler enables transformation of protobuf messages of the same
// type as keyProto into crypto.Signer by invoking the provided handler.
// The keyProto need only be an empty example of the type of protobuf message that
// the handler can process - only its type is examined.
// If a handler for this type of protobuf message has already been added, it will
// be replaced.
//
// The registration is published as a new immutable store generation; the
// previous generation is unaffected and remains usable via CurrentStore()
// snapshots taken before this call.
func RegisterHandler(keyProto proto.Message, handler ProtoHandler) {
	keyProtoType := keyProto.ProtoReflect().Descriptor().FullName()

	for {
		prev := CurrentStore()
		if _, alreadyExists := prev.handlers[keyProtoType]; alreadyExists {
			klog.Warningf("Overridding ProtoHandler for protobuf %q", keyProtoType)
		}
		if err := PublishStore(prev, prev.WithHandler(keyProto, handler)); err == nil {
			return
		}
		// Lost a race with a concurrent rotation; re-derive from the new
		// current generation and try again.
	}
}

// unregisterHandler removes a previously-added protobuf message handler.
// See RegisterHandler().
func unregisterHandler(keyProto proto.Message) {
	for {
		prev := CurrentStore()
		if err := PublishStore(prev, prev.WithoutHandler(keyProto)); err == nil {
			return
		}
	}
}

// RotateHandler attempts to rotate the backend for keyProto's protobuf type
// to handler. The candidate handler is exercised with keyProto before
// anything is published; if it fails, the current store generation is left
// untouched and an error is returned, so existing trees keep using the
// previous backend and already-created signers remain valid. The rotation
// can then be retried, e.g. with a fixed handler.
//
// On success the newly published store generation is returned. On validation
// failure the returned store is the (unchanged) current generation, which
// the caller may retain for recovery via RestoreStore.
func RotateHandler(ctx context.Context, keyProto proto.Message, handler ProtoHandler) (*Store, error) {
	if keyProto == nil {
		return CurrentStore(), fmt.Errorf("nil keyProto")
	}
	keyProtoType := keyProto.ProtoReflect().Descriptor().FullName()

	// Exercise the candidate handler before publishing so that a broken
	// backend never becomes the current generation.
	if _, err := handler(ctx, keyProto); err != nil {
		current := CurrentStore()
		return current, fmt.Errorf("rotation of ProtoHandler for protobuf %q failed validation, keeping store generation %d: %v",
			keyProtoType, current.Generation(), err)
	}

	for {
		prev := CurrentStore()
		next := prev.WithHandler(keyProto, handler)
		if err := PublishStore(prev, next); err == nil {
			return next, nil
		}
	}
}

// NewSigner uses a registered ProtoHandler (see RegisterHandler()) to convert a
// protobuf message into a crypto.Signer.
// If there is no ProtoHandler registered for this type of protobuf message, an
// error will be returned.
//
// The handler is selected from the current immutable store generation; the
// returned signer stays usable even if a later rotation replaces the handler
// it was created from.
func NewSigner(ctx context.Context, keyProto proto.Message) (crypto.Signer, error) {
	return CurrentStore().NewSigner(ctx, keyProto)
}
