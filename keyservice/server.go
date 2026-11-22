package keyservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hckms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is a key service server that uses SOPS MasterKeys to fulfill requests
type Server struct {
	// Prompt indicates whether the server should prompt before decrypting or encrypting data
	Prompt bool

	// Policy limits which callers may use which keys. When nil, all callers
	// that passed transport authentication (or were explicitly admitted by
	// AllowAnonymous) may use every key.
	Policy *Policy

	// AllowAnonymous explicitly admits unauthenticated network callers. It
	// is only accepted by the listener configuration for local addresses.
	AllowAnonymous bool

	// RequestTimeout bounds every backend operation. Zero disables the
	// timeout for the in-process client, preserving its behavior; the
	// network server always sets it.
	RequestTimeout time.Duration

	// Limiter bounds concurrency and admission rate. When nil, requests
	// are served immediately.
	Limiter *Limiter

	// Metrics records request counts, rejections, queue depth and in-flight
	// requests. When nil, no metrics are recorded.
	Metrics *Metrics

	// Audit receives one record per request decision. When nil, decisions
	// are not audited.
	Audit *AuditLogger

	// backendHook is a test seam invoked before the real backend operation.
	backendHook func(ctx context.Context) error
}

// Encrypt takes an encrypt request and encrypts the provided plaintext with the provided key, returning the encrypted
// result
func (ks Server) Encrypt(ctx context.Context,
	req *EncryptRequest) (*EncryptResponse, error) {
	plaintext, err := ks.dispatch(ctx, OpEncrypt, req.GetKey(), func(ctx context.Context) ([]byte, error) {
		return ks.encrypt(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return &EncryptResponse{Ciphertext: plaintext}, nil
}

// Decrypt takes a decrypt request and decrypts the provided ciphertext with the provided key, returning the decrypted
// result
func (ks Server) Decrypt(ctx context.Context,
	req *DecryptRequest) (*DecryptResponse, error) {
	plaintext, err := ks.dispatch(ctx, OpDecrypt, req.GetKey(), func(ctx context.Context) ([]byte, error) {
		return ks.decrypt(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return &DecryptResponse{Plaintext: plaintext}, nil
}

// dispatch applies the identity, scope, admission and timeout checks in order,
// then runs the backend operation. Every decision is audited before any key
// material is touched.
func (ks Server) dispatch(ctx context.Context, op Operation, key *Key, run func(context.Context) ([]byte, error)) ([]byte, error) {
	start := time.Now()
	id := CallerFromContext(ctx)
	keyType, _ := KeyTypeAndIdentifier(key)

	if ks.Metrics != nil {
		ks.Metrics.requests.Add(1)
	}

	finish := func(outcome, reason string) {
		if ks.Metrics != nil {
			switch outcome {
			case auditOutcomeAllowed:
				ks.Metrics.allowed.Add(1)
			case auditOutcomeDenied:
				ks.Metrics.denied.Add(1)
			default:
				ks.Metrics.errors.Add(1)
			}
		}
		if ks.Audit != nil {
			ks.Audit.Log(AuditEvent{
				Event:     "keyservice.request",
				Caller:    id.CallerID(),
				Operation: string(op),
				KeyType:   keyType,
				Outcome:   outcome,
				Reason:    reason,
				Peer:      id.Peer,
				Duration:  time.Since(start).String(),
			})
		}
	}

	// 1. Transport authentication. In-process callers (LocalClient) never
	//    traverse the network and are admitted as before.
	if !id.Local && !id.Authenticated {
		if !ks.AllowAnonymous {
			err := ErrAuthenticationRequired
			finish(auditOutcomeDenied, reasonOf(err))
			return nil, toGRPCError(err)
		}
		id.Anonymous = true
		if ks.Metrics != nil {
			ks.Metrics.anonymous.Add(1)
		}
	}

	// 2. Scope authorization. This runs before the limiter, before the
	//    interactive prompt and before any backend call.
	if err := ks.Policy.Authorize(id, op, key); err != nil {
		finish(auditOutcomeDenied, reasonOf(err))
		return nil, toGRPCError(err)
	}

	// 3. Admission control (rate limiting and bounded queueing).
	if err := ks.Limiter.Acquire(ctx); err != nil {
		finish(auditOutcomeDenied, reasonOf(err))
		return nil, toGRPCError(err)
	}
	defer ks.Limiter.Release()

	// 4. Interactive confirmation, before the key material is touched.
	if ks.Prompt {
		if err := ks.prompt(key, string(op)); err != nil {
			finish(auditOutcomeDenied, auditPromptRejected)
			return nil, err
		}
	}

	if ks.Metrics != nil {
		ks.Metrics.inFlight.Add(1)
		defer ks.Metrics.inFlight.Add(-1)
	}

	// 5. Backend operation under a deadline.
	backend := run
	if ks.backendHook != nil {
		hook := ks.backendHook
		inner := backend
		backend = func(ctx context.Context) ([]byte, error) {
			if err := hook(ctx); err != nil {
				return nil, err
			}
			return inner(ctx)
		}
	}
	result, err := callBackend(ctx, ks.RequestTimeout, backend)
	if err != nil {
		// A backend failure, timeout or cancel is an error, never a
		// denial: callers can distinguish the two via the status code.
		if ks.Metrics != nil && errors.Is(err, ErrBackendTimeout) {
			ks.Metrics.backendTimeouts.Add(1)
		}
		finish(auditOutcomeError, reasonOf(err))
		return nil, toGRPCError(err)
	}
	finish(auditOutcomeAllowed, auditAllowedReason)
	return result, nil
}

// callBackend runs fn with an optional timeout. The backend runs in its own
// goroutine so that a hung backend cannot hold the RPC handler: when the
// deadline fires the request is abandoned and the deadline is propagated to
// context-aware backends, releasing their connection. The buffered channel
// guarantees the goroutine can always deliver its result and exit.
func callBackend(ctx context.Context, timeout time.Duration, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if timeout <= 0 {
		return fn(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		value []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := fn(ctx)
		done <- result{value: value, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ErrBackendTimeout
			}
			return nil, ctx.Err()
		}
		return r.value, r.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrBackendTimeout
		}
		return nil, ctx.Err()
	}
}

// statusError is a gRPC status error that also preserves the underlying error
// chain, so in-process callers can use errors.Is while remote callers receive
// the standard gRPC status code.
type statusError struct {
	st  *status.Status
	err error
}

func (e *statusError) Error() string              { return e.st.Err().Error() }
func (e *statusError) GRPCStatus() *status.Status { return e.st }
func (e *statusError) Unwrap() error              { return e.err }

func newStatusError(code codes.Code, err error) error {
	return &statusError{st: status.New(code, err.Error()), err: err}
}

// toGRPCError maps the internal errors to identifiable gRPC status codes.
// Authorization errors are sanitized: they never contain key identifiers or
// key material.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		// Already a gRPC status error (e.g. the key-not-found and
		// prompt-rejected paths): pass it through unchanged.
		return err
	}
	switch {
	case errors.Is(err, ErrAuthenticationRequired):
		return newStatusError(codes.Unauthenticated, err)
	case errors.Is(err, ErrCallerNotAuthorized), errors.Is(err, ErrKeyOutOfScope):
		return newStatusError(codes.PermissionDenied, err)
	case errors.Is(err, ErrRateLimited), errors.Is(err, ErrQueueFull), errors.Is(err, ErrQueueTimeout):
		return newStatusError(codes.ResourceExhausted, err)
	case errors.Is(err, ErrBackendTimeout):
		return newStatusError(codes.DeadlineExceeded, err)
	case errors.Is(err, context.Canceled):
		return newStatusError(codes.Canceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return newStatusError(codes.DeadlineExceeded, err)
	default:
		return err
	}
}

func (ks Server) encrypt(ctx context.Context, req *EncryptRequest) ([]byte, error) {
	key := req.GetKey()
	if key == nil || key.KeyType == nil {
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	}
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		return ks.encryptWithPgp(ctx, k.PgpKey, req.Plaintext)
	case *Key_KmsKey:
		return ks.encryptWithKms(ctx, k.KmsKey, req.Plaintext)
	case *Key_GcpKmsKey:
		return ks.encryptWithGcpKms(ctx, k.GcpKmsKey, req.Plaintext)
	case *Key_AzureKeyvaultKey:
		return ks.encryptWithAzureKeyVault(ctx, k.AzureKeyvaultKey, req.Plaintext)
	case *Key_VaultKey:
		return ks.encryptWithVault(ctx, k.VaultKey, req.Plaintext)
	case *Key_AgeKey:
		return ks.encryptWithAge(ctx, k.AgeKey, req.Plaintext)
	case *Key_HckmsKey:
		return ks.encryptWithHckms(ctx, k.HckmsKey, req.Plaintext)
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}
}

func (ks Server) decrypt(ctx context.Context, req *DecryptRequest) ([]byte, error) {
	key := req.GetKey()
	if key == nil || key.KeyType == nil {
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	}
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		return ks.decryptWithPgp(ctx, k.PgpKey, req.Ciphertext)
	case *Key_KmsKey:
		return ks.decryptWithKms(ctx, k.KmsKey, req.Ciphertext)
	case *Key_GcpKmsKey:
		return ks.decryptWithGcpKms(ctx, k.GcpKmsKey, req.Ciphertext)
	case *Key_AzureKeyvaultKey:
		return ks.decryptWithAzureKeyVault(ctx, k.AzureKeyvaultKey, req.Ciphertext)
	case *Key_VaultKey:
		return ks.decryptWithVault(ctx, k.VaultKey, req.Ciphertext)
	case *Key_AgeKey:
		return ks.decryptWithAge(ctx, k.AgeKey, req.Ciphertext)
	case *Key_HckmsKey:
		return ks.decryptWithHckms(ctx, k.HckmsKey, req.Ciphertext)
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}
}

func (ks *Server) encryptWithPgp(ctx context.Context, key *PgpKey, plaintext []byte) ([]byte, error) {
	pgpKey := pgp.NewMasterKeyFromFingerprint(key.Fingerprint)
	err := pgpKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(pgpKey.EncryptedKey), nil
}

func (ks *Server) encryptWithKms(ctx context.Context, key *KmsKey, plaintext []byte) ([]byte, error) {
	kmsKey := kmsKeyToMasterKey(key)
	err := kmsKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(kmsKey.EncryptedKey), nil
}

func (ks *Server) encryptWithGcpKms(ctx context.Context, key *GcpKmsKey, plaintext []byte) ([]byte, error) {
	gcpKmsKey := gcpkms.MasterKey{
		ResourceID: key.ResourceId,
	}
	err := gcpKmsKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(gcpKmsKey.EncryptedKey), nil
}

func (ks *Server) encryptWithAzureKeyVault(ctx context.Context, key *AzureKeyVaultKey, plaintext []byte) ([]byte, error) {
	azkvKey := azkv.MasterKey{
		VaultURL: key.VaultUrl,
		Name:     key.Name,
		Version:  key.Version,
	}
	err := azkvKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(azkvKey.EncryptedKey), nil
}

func (ks *Server) encryptWithHckms(ctx context.Context, key *HckmsKey, plaintext []byte) ([]byte, error) {
	hckmsKey, err := hckms.NewMasterKey(key.KeyId)
	if err != nil {
		return nil, err
	}
	err = hckmsKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(hckmsKey.EncryptedKey), nil
}

func (ks *Server) encryptWithVault(ctx context.Context, key *VaultKey, plaintext []byte) ([]byte, error) {
	vaultKey := hcvault.MasterKey{
		VaultAddress: key.VaultAddress,
		EnginePath:   key.EnginePath,
		KeyName:      key.KeyName,
	}
	err := vaultKey.EncryptContext(ctx, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(vaultKey.EncryptedKey), nil
}

func (ks *Server) encryptWithAge(ctx context.Context, key *AgeKey, plaintext []byte) ([]byte, error) {
	ageKey := age.MasterKey{
		Recipient: key.Recipient,
	}

	if err := ageKey.Encrypt(plaintext); err != nil {
		return nil, err
	}

	return []byte(ageKey.EncryptedKey), nil
}

func (ks *Server) decryptWithPgp(ctx context.Context, key *PgpKey, ciphertext []byte) ([]byte, error) {
	pgpKey := pgp.NewMasterKeyFromFingerprint(key.Fingerprint)
	pgpKey.EncryptedKey = string(ciphertext)
	plaintext, err := pgpKey.DecryptContext(ctx)
	return []byte(plaintext), err
}

func (ks *Server) decryptWithKms(ctx context.Context, key *KmsKey, ciphertext []byte) ([]byte, error) {
	kmsKey := kmsKeyToMasterKey(key)
	kmsKey.EncryptedKey = string(ciphertext)
	plaintext, err := kmsKey.DecryptContext(ctx)
	return []byte(plaintext), err
}

func (ks *Server) decryptWithGcpKms(ctx context.Context, key *GcpKmsKey, ciphertext []byte) ([]byte, error) {
	gcpKmsKey := gcpkms.MasterKey{
		ResourceID: key.ResourceId,
	}
	gcpKmsKey.EncryptedKey = string(ciphertext)
	plaintext, err := gcpKmsKey.DecryptContext(ctx)
	return []byte(plaintext), err
}

func (ks *Server) decryptWithAzureKeyVault(ctx context.Context, key *AzureKeyVaultKey, ciphertext []byte) ([]byte, error) {
	azkvKey := azkv.MasterKey{
		VaultURL: key.VaultUrl,
		Name:     key.Name,
		Version:  key.Version,
	}
	azkvKey.EncryptedKey = string(ciphertext)
	plaintext, err := azkvKey.DecryptContext(ctx)
	return []byte(plaintext), err
}

func (ks *Server) decryptWithHckms(ctx context.Context, key *HckmsKey, ciphertext []byte) ([]byte, error) {
	hckmsKey, err := hckms.NewMasterKey(key.KeyId)
	if err != nil {
		return nil, err
	}
	hckmsKey.EncryptedKey = string(ciphertext)
	plaintext, err := hckmsKey.DecryptContext(ctx)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (ks *Server) decryptWithVault(ctx context.Context, key *VaultKey, ciphertext []byte) ([]byte, error) {
	vaultKey := hcvault.MasterKey{
		VaultAddress: key.VaultAddress,
		EnginePath:   key.EnginePath,
		KeyName:      key.KeyName,
	}
	vaultKey.EncryptedKey = string(ciphertext)
	plaintext, err := vaultKey.DecryptContext(ctx)
	return []byte(plaintext), err
}

func (ks *Server) decryptWithAge(ctx context.Context, key *AgeKey, ciphertext []byte) ([]byte, error) {
	ageKey := age.MasterKey{
		Recipient: key.Recipient,
	}
	ageKey.EncryptedKey = string(ciphertext)
	plaintext, err := ageKey.Decrypt()
	return []byte(plaintext), err
}

func keyToString(key *Key) string {
	if key == nil {
		return "Unknown key type"
	}
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		return fmt.Sprintf("PGP key with fingerprint %s", k.PgpKey.Fingerprint)
	case *Key_KmsKey:
		return fmt.Sprintf("AWS KMS key with ARN %s", k.KmsKey.Arn)
	case *Key_GcpKmsKey:
		return fmt.Sprintf("GCP KMS key with resource ID %s", k.GcpKmsKey.ResourceId)
	case *Key_AzureKeyvaultKey:
		return fmt.Sprintf("Azure Key Vault key with URL %s/keys/%s/%s", k.AzureKeyvaultKey.VaultUrl, k.AzureKeyvaultKey.Name, k.AzureKeyvaultKey.Version)
	case *Key_VaultKey:
		return fmt.Sprintf("Hashicorp Vault key with URI %s/v1/%s/keys/%s", k.VaultKey.VaultAddress, k.VaultKey.EnginePath, k.VaultKey.KeyName)
	case *Key_HckmsKey:
		return fmt.Sprintf("HuaweiCloud KMS key with ID %s", k.HckmsKey.KeyId)
	case *Key_AgeKey:
		return fmt.Sprintf("age key with recipient %s", k.AgeKey.Recipient)
	default:
		return "Unknown key type"
	}
}

func (ks Server) prompt(key *Key, requestType string) error {
	keyString := keyToString(key)
	var response string
	for response != "y" && response != "n" {
		fmt.Printf("\nReceived %s request using %s. Respond to request? (y/n): ", requestType, keyString)
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
	}
	if response == "n" {
		return status.Errorf(codes.PermissionDenied, "Request rejected by user")
	}
	return nil
}

func kmsKeyToMasterKey(key *KmsKey) kms.MasterKey {
	ctx := make(map[string]*string)
	for k, v := range key.Context {
		value := v // Allocate a new string to prevent the pointer below from referring to only the last iteration value
		ctx[k] = &value
	}
	return kms.MasterKey{
		Arn:               key.Arn,
		Role:              key.Role,
		EncryptionContext: ctx,
		AwsProfile:        key.AwsProfile,
	}
}
