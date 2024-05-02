package auth_module

import (
	"errors"
	"testing"
)

func TestFailedToken(t *testing.T) {
	t.Run("with no arguments", func(t *testing.T) {
		valid, _, err := failedToken()
		if valid {
			t.Errorf("expected valid to be false, got %v", valid)
		}
		if err.Error() != "token not valid" {
			t.Errorf("expected error to be 'token not valid', got %v", err)
		}
	})

	t.Run("with string argument", func(t *testing.T) {
		valid, _, err := failedToken("custom error message")
		if valid {
			t.Errorf("expected valid to be false, got %v", valid)
		}
		if err.Error() != "custom error message" {
			t.Errorf("expected error to be 'custom error message', got %v", err)
		}
	})

	t.Run("with non-string argument", func(t *testing.T) {
		valid, _, err := failedToken(errors.New("error object"))
		if valid {
			t.Errorf("expected valid to be false, got %v", valid)
		}
		if err.Error() != "token not valid" {
			t.Errorf("expected error to be 'token not valid', got %v", err)
		}
	})

	t.Run("with non-string argument", func(t *testing.T) {
		ref := struct{ Name int }{Name: 10}
		valid, _, err := failedToken(&ref)
		if valid {
			t.Errorf("expected valid to be false, got %v", valid)
		}
		if err.Error() != "token not valid" {
			t.Errorf("expected error to be 'token not valid', got %v", err)
		}
	})
}
