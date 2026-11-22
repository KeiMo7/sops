package keyservice

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Operation is the class of a key service request. It is used in scope rules
// and audit records.
type Operation string

const (
	// OpEncrypt is an Encrypt RPC.
	OpEncrypt Operation = "encrypt"
	// OpDecrypt is a Decrypt RPC.
	OpDecrypt Operation = "decrypt"
)

func (op Operation) valid() bool {
	return op == OpEncrypt || op == OpDecrypt
}

// ScopeRule assigns a set of keys and operations to a group of callers.
//
// Callers is a list of caller identifiers or glob patterns. An authenticated
// caller matches with its certificate common name ("ops-client" or
// "CN=ops-client"), its DNS SANs ("DNS=client.example.com" or
// "client.example.com") or its URI SANs ("URI=spiffe://example.org/ns/ops" or
// the bare URI). The special values "anonymous" and "local" match
// unauthenticated callers admitted by anonymous mode and in-process calls.
//
// Keys is a list of "<type>" or "<type>:<identifier glob>" patterns. The type
// is one of kms, pgp, gcp_kms, azure_kv, hc_vault, age, hckms. A bare type
// allows every key of that type; "*" allows every key. The identifier glob
// supports "*" and "?".
//
// Operations restricts the rule to decrypt and/or encrypt. An empty list
// means both.
type ScopeRule struct {
	Name       string   `yaml:"name" json:"name"`
	Callers    []string `yaml:"callers" json:"callers"`
	Keys       []string `yaml:"keys" json:"keys"`
	Operations []string `yaml:"operations,omitempty" json:"operations,omitempty"`

	callerMatchers []*regexp.Regexp
	keyMatchers    []scopeKeyMatcher
	operations     map[Operation]bool
}

// Policy is an ordered list of scope rules. The first matching rule decides
// whether a request is allowed; a caller that matches no rule is denied.
type Policy struct {
	Rules []ScopeRule `yaml:"rules" json:"rules"`
}

type scopeKeyMatcher struct {
	keyType string
	idGlob  *regexp.Regexp
}

// LoadPolicy parses and validates a YAML or JSON policy file. Any syntax or
// semantic error is returned, so that operators can catch broken range rules
// at startup instead of at request time.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyservice: cannot read policy file: %w", err)
	}
	var policy Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return nil, fmt.Errorf("keyservice: invalid policy file %q: %w", path, err)
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("keyservice: invalid policy file %q: %w", path, err)
	}
	return &policy, nil
}

var knownKeyTypes = map[string]bool{
	"kms":      true,
	"pgp":      true,
	"gcp_kms":  true,
	"azure_kv": true,
	"hc_vault": true,
	"age":      true,
	"hckms":    true,
}

// Validate checks every rule and compiles its patterns. It is called at
// startup, before the listener is created.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	for i := range p.Rules {
		rule := &p.Rules[i]
		name := rule.Name
		if name == "" {
			name = fmt.Sprintf("rule[%d]", i)
		}
		if len(rule.Callers) == 0 {
			return fmt.Errorf("%s: at least one caller is required", name)
		}
		if len(rule.Keys) == 0 {
			return fmt.Errorf("%s: at least one key scope is required", name)
		}
		rule.callerMatchers = rule.callerMatchers[:0]
		for _, caller := range rule.Callers {
			if strings.TrimSpace(caller) == "" {
				return fmt.Errorf("%s: empty caller pattern", name)
			}
			re, err := compileGlob(caller)
			if err != nil {
				return fmt.Errorf("%s: invalid caller pattern %q: %w", name, caller, err)
			}
			rule.callerMatchers = append(rule.callerMatchers, re)
		}
		rule.keyMatchers = rule.keyMatchers[:0]
		for _, scope := range rule.Keys {
			matcher, err := parseScopeKeyPattern(scope)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			rule.keyMatchers = append(rule.keyMatchers, matcher)
		}
		rule.operations = make(map[Operation]bool)
		for _, op := range rule.Operations {
			operation := Operation(strings.ToLower(strings.TrimSpace(op)))
			if !operation.valid() {
				return fmt.Errorf("%s: invalid operation %q (want encrypt or decrypt)", name, op)
			}
			rule.operations[operation] = true
		}
	}
	return nil
}

func parseScopeKeyPattern(pattern string) (scopeKeyMatcher, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return scopeKeyMatcher{}, fmt.Errorf("empty key scope pattern")
	}
	if pattern == "*" {
		re, _ := compileGlob("*")
		return scopeKeyMatcher{keyType: "*", idGlob: re}, nil
	}
	keyType := pattern
	idPattern := "*"
	if idx := strings.Index(pattern, ":"); idx >= 0 {
		keyType = pattern[:idx]
		idPattern = pattern[idx+1:]
	}
	if keyType != "*" && !knownKeyTypes[keyType] {
		return scopeKeyMatcher{}, fmt.Errorf("unknown key type %q in scope pattern %q", keyType, pattern)
	}
	re, err := compileGlob(idPattern)
	if err != nil {
		return scopeKeyMatcher{}, fmt.Errorf("invalid key scope pattern %q: %w", pattern, err)
	}
	return scopeKeyMatcher{keyType: keyType, idGlob: re}, nil
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func (rule ScopeRule) matchesCaller(id CallerIdentity) bool {
	if len(rule.callerMatchers) == 0 {
		// Validate normally compiles these; keep a safe fallback for
		// policies constructed directly in tests.
		for _, pattern := range rule.Callers {
			re, err := compileGlob(pattern)
			if err != nil {
				continue
			}
			for _, candidate := range id.candidates() {
				if re.MatchString(candidate) {
					return true
				}
			}
		}
		return false
	}
	for _, re := range rule.callerMatchers {
		for _, candidate := range id.candidates() {
			if re.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

func (rule ScopeRule) allowsOperation(op Operation) bool {
	if len(rule.operations) == 0 {
		return true
	}
	return rule.operations[op]
}

func (rule ScopeRule) allowsKey(keyType, identifier string) bool {
	if len(rule.keyMatchers) == 0 {
		for _, pattern := range rule.Keys {
			matcher, err := parseScopeKeyPattern(pattern)
			if err != nil {
				continue
			}
			if matcher.matches(keyType, identifier) {
				return true
			}
		}
		return false
	}
	for _, matcher := range rule.keyMatchers {
		if matcher.matches(keyType, identifier) {
			return true
		}
	}
	return false
}

func (m scopeKeyMatcher) matches(keyType, identifier string) bool {
	if m.keyType != "*" && m.keyType != keyType {
		return false
	}
	if m.idGlob == nil {
		return true
	}
	return m.idGlob.MatchString(identifier)
}

// Authorize decides whether the caller may run op against key. It never
// touches key material, and the returned errors never contain key
// identifiers.
func (p *Policy) Authorize(id CallerIdentity, op Operation, key *Key) error {
	if p == nil || len(p.Rules) == 0 {
		// No policy configured: the listener and transport configuration
		// decide who may reach this point. Authenticated and explicitly
		// admitted anonymous callers are trusted with the full key set.
		if id.Authenticated || id.Anonymous || id.Local {
			return nil
		}
		return ErrAuthenticationRequired
	}
	keyType, identifier := KeyTypeAndIdentifier(key)
	callerMatched := false
	for _, rule := range p.Rules {
		if !rule.matchesCaller(id) {
			continue
		}
		callerMatched = true
		if !rule.allowsOperation(op) {
			continue
		}
		if rule.allowsKey(keyType, identifier) {
			return nil
		}
	}
	if !callerMatched {
		return ErrCallerNotAuthorized
	}
	return ErrKeyOutOfScope
}

// KeyTypeAndIdentifier returns the scope type name and the public identifier
// of an RPC key. The identifier is used for matching only; it is never written
// to audit records or returned in authorization errors.
func KeyTypeAndIdentifier(key *Key) (keyType string, identifier string) {
	if key == nil {
		return "", ""
	}
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		return "pgp", k.PgpKey.GetFingerprint()
	case *Key_KmsKey:
		return "kms", k.KmsKey.GetArn()
	case *Key_GcpKmsKey:
		return "gcp_kms", k.GcpKmsKey.GetResourceId()
	case *Key_AzureKeyvaultKey:
		return "azure_kv", fmt.Sprintf("%s/keys/%s/%s", k.AzureKeyvaultKey.GetVaultUrl(), k.AzureKeyvaultKey.GetName(), k.AzureKeyvaultKey.GetVersion())
	case *Key_VaultKey:
		return "hc_vault", fmt.Sprintf("%s/v1/%s/keys/%s", k.VaultKey.GetVaultAddress(), k.VaultKey.GetEnginePath(), k.VaultKey.GetKeyName())
	case *Key_AgeKey:
		return "age", k.AgeKey.GetRecipient()
	case *Key_HckmsKey:
		return "hckms", k.HckmsKey.GetKeyId()
	default:
		return "", ""
	}
}
