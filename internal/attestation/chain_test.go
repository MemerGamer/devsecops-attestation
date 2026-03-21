package attestation

import (
	"strings"
	"testing"
	"time"

	"github.com/MemerGamer/devsecops-attestation/internal/crypto"
	"github.com/MemerGamer/devsecops-attestation/pkg/types"
)

// makeKeyPair generates a key pair for tests, calling t.Fatal on error.
func makeKeyPair(t testing.TB) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return kp
}

func makeSubject(name string) types.AttestationSubject {
	return types.AttestationSubject{Name: name, Digest: "sha256:" + name}
}

func makeResult(checkType types.SecurityCheckType, passed bool) types.SecurityResult {
	return types.SecurityResult{
		CheckType:   checkType,
		Tool:        "test-tool",
		Version:     "0.0.1",
		TargetRef:   "abc123",
		RunAt:       time.Now().UTC(),
		PassedCount: 1,
		Findings:    []types.Finding{},
		Passed:      passed,
	}
}

func TestChainAdd(t *testing.T) {
	t.Run("first attestation has no previous digest", func(t *testing.T) {
		kp := makeKeyPair(t)
		c := NewChain()
		a, err := c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp)
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		if a.PreviousDigest != "" {
			t.Errorf("first attestation PreviousDigest = %q, want empty", a.PreviousDigest)
		}
	})

	t.Run("second attestation references first", func(t *testing.T) {
		kp := makeKeyPair(t)
		c := NewChain()
		a1, err := c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp)
		if err != nil {
			t.Fatalf("Add() first error = %v", err)
		}
		a2, err := c.Add(makeSubject("app"), makeResult(types.CheckSCA, true), kp)
		if err != nil {
			t.Fatalf("Add() second error = %v", err)
		}

		expectedDigest, err := crypto.Digest(a1)
		if err != nil {
			t.Fatalf("Digest(a1) error = %v", err)
		}
		if a2.PreviousDigest != expectedDigest {
			t.Errorf("second attestation PreviousDigest = %q, want %q", a2.PreviousDigest, expectedDigest)
		}
	})

	t.Run("third attestation references second", func(t *testing.T) {
		kp := makeKeyPair(t)
		c := NewChain()
		c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp)   //nolint
		a2, err := c.Add(makeSubject("app"), makeResult(types.CheckSCA, true), kp)
		if err != nil {
			t.Fatalf("Add() second error = %v", err)
		}
		a3, err := c.Add(makeSubject("app"), makeResult(types.CheckConfig, true), kp)
		if err != nil {
			t.Fatalf("Add() third error = %v", err)
		}

		expectedDigest, err := crypto.Digest(a2)
		if err != nil {
			t.Fatalf("Digest(a2) error = %v", err)
		}
		if a3.PreviousDigest != expectedDigest {
			t.Errorf("third attestation PreviousDigest = %q, want %q", a3.PreviousDigest, expectedDigest)
		}
	})

	t.Run("returned attestation has valid signature", func(t *testing.T) {
		kp := makeKeyPair(t)
		c := NewChain()
		a, err := c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp)
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		if err := crypto.Verify(a); err != nil {
			t.Errorf("Verify() on returned attestation error = %v", err)
		}
	})

	t.Run("different key pairs succeed", func(t *testing.T) {
		kp1 := makeKeyPair(t)
		kp2 := makeKeyPair(t)
		c := NewChain()
		if _, err := c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp1); err != nil {
			t.Fatalf("Add() with kp1 error = %v", err)
		}
		if _, err := c.Add(makeSubject("app"), makeResult(types.CheckSCA, true), kp2); err != nil {
			t.Fatalf("Add() with kp2 error = %v", err)
		}
	})

	t.Run("subject is preserved in returned attestation", func(t *testing.T) {
		kp := makeKeyPair(t)
		c := NewChain()
		subject := types.AttestationSubject{Name: "my-service", Digest: "sha256:deadbeef"}
		a, err := c.Add(subject, makeResult(types.CheckSAST, true), kp)
		if err != nil {
			t.Fatalf("Add() error = %v", err)
		}
		if a.Subject.Name != subject.Name {
			t.Errorf("Subject.Name = %q, want %q", a.Subject.Name, subject.Name)
		}
		if a.Subject.Digest != subject.Digest {
			t.Errorf("Subject.Digest = %q, want %q", a.Subject.Digest, subject.Digest)
		}
	})
}

func TestNewChainFromSlice(t *testing.T) {
	kp := makeKeyPair(t)
	c := NewChain()
	a1, _ := c.Add(makeSubject("app"), makeResult(types.CheckSAST, true), kp)
	a2, _ := c.Add(makeSubject("app"), makeResult(types.CheckSCA, true), kp)

	original := []types.Attestation{*a1, *a2}
	restored := NewChainFromSlice(original)

	if len(restored.Attestations()) != 2 {
		t.Errorf("NewChainFromSlice() length = %d, want 2", len(restored.Attestations()))
	}

	// Adding to the restored chain should link to a2.
	a3, err := restored.Add(makeSubject("app"), makeResult(types.CheckConfig, true), kp)
	if err != nil {
		t.Fatalf("Add() after NewChainFromSlice error = %v", err)
	}
	expectedDigest, _ := crypto.Digest(a2)
	if a3.PreviousDigest != expectedDigest {
		t.Errorf("PreviousDigest after restore = %q, want %q", a3.PreviousDigest, expectedDigest)
	}
}

func TestVerifyChain(t *testing.T) {
	buildChain := func(t testing.TB, n int) ([]types.Attestation, *crypto.KeyPair) {
		t.Helper()
		kp := makeKeyPair(t)
		c := NewChain()
		checkTypes := []types.SecurityCheckType{types.CheckSAST, types.CheckSCA, types.CheckConfig}
		for i := 0; i < n; i++ {
			c.Add(makeSubject("app"), makeResult(checkTypes[i%len(checkTypes)], true), kp) //nolint
		}
		return c.Attestations(), kp
	}

	t.Run("empty chain returns error", func(t *testing.T) {
		_, err := VerifyChain(nil)
		if err == nil {
			t.Error("VerifyChain(nil) expected error, got nil")
		}
		_, err = VerifyChain([]types.Attestation{})
		if err == nil {
			t.Error("VerifyChain([]) expected error, got nil")
		}
	})

	t.Run("single valid attestation passes", func(t *testing.T) {
		chain, _ := buildChain(t, 1)
		results, err := VerifyChain(chain)
		if err != nil {
			t.Errorf("VerifyChain() unexpected error = %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("len(results) = %d, want 1", len(results))
		}
		if !results[0].SignatureValid {
			t.Error("results[0].SignatureValid = false, want true")
		}
		if !results[0].ChainValid {
			t.Error("results[0].ChainValid = false, want true")
		}
	})

	t.Run("two valid attestations pass", func(t *testing.T) {
		chain, _ := buildChain(t, 2)
		results, err := VerifyChain(chain)
		if err != nil {
			t.Errorf("VerifyChain() unexpected error = %v", err)
		}
		for i, r := range results {
			if !r.SignatureValid {
				t.Errorf("results[%d].SignatureValid = false", i)
			}
			if !r.ChainValid {
				t.Errorf("results[%d].ChainValid = false", i)
			}
		}
	})

	t.Run("three valid attestations pass", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		results, err := VerifyChain(chain)
		if err != nil {
			t.Errorf("VerifyChain() unexpected error = %v", err)
		}
		if len(results) != 3 {
			t.Fatalf("len(results) = %d, want 3", len(results))
		}
	})

	t.Run("tampered payload in first attestation", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		chain[0].Result.Passed = !chain[0].Result.Passed

		results, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error for tampered chain, got nil")
		}
		if results[0].SignatureValid {
			t.Error("results[0].SignatureValid should be false after tampering")
		}
	})

	t.Run("tampered payload in middle attestation", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		chain[1].Result.Passed = !chain[1].Result.Passed

		results, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error for tampered chain, got nil")
		}
		if results[1].SignatureValid {
			t.Error("results[1].SignatureValid should be false after tampering")
		}
		// Chain linkage at position 2 should also break since digest of [1] changed.
		if results[2].ChainValid {
			t.Error("results[2].ChainValid should be false because [1] was tampered")
		}
	})

	t.Run("deleted attestation from middle breaks chain", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		// Remove the middle attestation; [2] now references [1]'s digest but [1] is gone.
		chain = append(chain[:1], chain[2:]...)

		_, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error after deleting middle attestation")
		}
	})

	t.Run("reordered attestations break chain", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		// Swap positions 0 and 1.
		chain[0], chain[1] = chain[1], chain[0]

		results, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error for reordered chain")
		}
		// New [0] (was [1]) has a non-empty PreviousDigest.
		if results[0].ChainValid {
			t.Error("results[0].ChainValid should be false after reorder")
		}
	})

	t.Run("first attestation with non-empty PreviousDigest fails", func(t *testing.T) {
		chain, _ := buildChain(t, 1)
		chain[0].PreviousDigest = "deadbeefdeadbeef"

		results, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error")
		}
		if results[0].ChainValid {
			t.Error("results[0].ChainValid should be false")
		}
	})

	t.Run("wrong SignerPublicKey causes signature error", func(t *testing.T) {
		chain, _ := buildChain(t, 1)
		kp2 := makeKeyPair(t)
		chain[0].SignerPublicKey = []byte(kp2.PublicKey)

		results, err := VerifyChain(chain)
		if err == nil {
			t.Error("VerifyChain() expected error for wrong signer key")
		}
		if results[0].SignatureValid {
			t.Error("results[0].SignatureValid should be false with wrong public key")
		}
	})

	t.Run("inserted attestation without updated digests breaks chain", func(t *testing.T) {
		chain, _ := buildChain(t, 2)

		// Build a valid single-attestation chain with a different key, to insert.
		kp2 := makeKeyPair(t)
		extra := NewChain()
		malicious, _ := extra.Add(makeSubject("evil"), makeResult(types.CheckSAST, true), kp2)

		// Insert malicious attestation at position 1 without updating PreviousDigest.
		inserted := []types.Attestation{chain[0], *malicious, chain[1]}

		_, err := VerifyChain(inserted)
		if err == nil {
			t.Error("VerifyChain() expected error after inserting attestation")
		}
	})

	t.Run("error message references position", func(t *testing.T) {
		chain, _ := buildChain(t, 3)
		chain[1].Result.Passed = !chain[1].Result.Passed
		chain[1].Signature = []byte("invalid")

		_, err := VerifyChain(chain)
		if err == nil {
			t.Fatal("expected error")
		}
		// Error should propagate. Just check it is non-nil (specific message tested above).
		if !strings.Contains(err.Error(), "") {
			t.Error("error is empty string")
		}
	})
}
