package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestHasSmallOrder_BlacklistedPoints(t *testing.T) {
	for i, p := range smallOrderPoints {
		if !hasSmallOrder(p[:]) {
			t.Errorf("hasSmallOrder rejected blacklist entry %d", i)
		}
	}
}

func TestHasSmallOrder_HonestKey(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if hasSmallOrder(priv.PublicKey().Bytes()) {
		t.Errorf("honest derived pub key flagged as small-order")
	}
}

func TestRejectSmallOrderPoint_RejectsBlacklist(t *testing.T) {
	for i, p := range smallOrderPoints {
		if err := rejectSmallOrderPoint(p[:]); err == nil {
			t.Errorf("rejectSmallOrderPoint accepted blacklist entry %d", i)
		}
	}
}

func TestRejectSmallOrderPoint_AcceptsHonest(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := rejectSmallOrderPoint(priv.PublicKey().Bytes()); err != nil {
		t.Errorf("rejectSmallOrderPoint refused honest key: %v", err)
	}
}
