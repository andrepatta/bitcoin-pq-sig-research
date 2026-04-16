package crypto

import (
	"testing"
	"time"
)

// TestPaperParamsKeygen exercises paper SPHINCS+ parameters to surface
// real timings and prove the geometry runs end-to-end. Skipped under
// -short since full run can take >30s.
func TestPaperParamsKeygen(t *testing.T) {
	if testing.Short() {
		t.Skip("paper-params keygen takes several seconds; skipped under -short")
	}

	t.Run("SHRINCS_keygen", func(t *testing.T) {
		start := time.Now()
		_, err := NewShrincsKey(t.Context(), testSeed(0xA0), NewShrincsFileIO(tmpStateFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("SHRINCS paper keygen: %s", time.Since(start))
	})

	t.Run("SHRIMPS_keygen_and_sign", func(t *testing.T) {
		start := time.Now()
		k, err := NewShrimpsKey(t.Context(), testSeed(0xA1), NewShrimpsFileIO(tmpStateFile(t)), 1024, 1)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("SHRIMPS paper keygen: %s", time.Since(start))

		msg := []byte("paper-params smoke")
		start = time.Now()
		sig, err := k.Sign(t.Context(), msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("SHRIMPS paper Sign (compact path): %s, sig %d B", time.Since(start), len(SerializeShrimpsSig(sig)))

		start = time.Now()
		if !VerifyShrimps(k.PublicKey, msg, sig) {
			t.Fatal("VerifyShrimps rejected valid sig")
		}
		t.Logf("SHRIMPS paper Verify: %s", time.Since(start))
	})

	t.Run("SHRINCS_sign_stateful", func(t *testing.T) {
		k, err := NewShrincsKey(t.Context(), testSeed(0xA2), NewShrincsFileIO(tmpStateFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("shrincs stateful")
		start := time.Now()
		sig, err := k.Sign(t.Context(), msg)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("SHRINCS paper Sign (stateful path): %s, sig %d B", time.Since(start), len(SerializeShrincsSig(sig)))

		start = time.Now()
		if !VerifyShrincs(k.PublicKey, msg, sig) {
			t.Fatal("VerifyShrincs rejected valid stateful sig")
		}
		t.Logf("SHRINCS paper Verify: %s", time.Since(start))
	})
}
