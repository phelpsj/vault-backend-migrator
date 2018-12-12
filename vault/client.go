package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
)

type Vault struct {
	c *api.Client
}

func (v *Vault) Client() *api.Client {
	return v.c
}

func NewClient() (*Vault, error) {
	cfg := api.DefaultConfig()

	// Read vault env variables
	cfg.ReadEnvironment()

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Sanity checks
	if v := os.Getenv(api.EnvVaultAddress); v == "" {
		fmt.Println("Did you mean to use localhost vault? Try setting VAULT_ADDR")
	}

	return &Vault{
		c: client,
	}, nil
}

// List the keys at at given vault path. This has only been tested on the generic backend.
// It will return nil if something goes wrong.
func (v *Vault) List(path string) []string {
	secret, err := v.c.Logical().List(path)
	if secret == nil {
		return nil
	}
	if err != nil {
		fmt.Printf("Unable to read path %q, err=%v\n", path, err)
		return nil
	}

	r, ok := secret.Data["keys"].([]interface{})
	if ok {
		out := make([]string, len(r))
		for i := range r {
			out[i] = r[i].(string)
		}
		return out
	}
	return nil
}

// Read accepts a vault path to read the data out of. It will return a map
// of base64 encoded values.
func (v *Vault) Read(path string) map[string]string {
	out := make(map[string]string)

	s, err := v.c.Logical().Read(path)
	if err != nil {
		fmt.Printf("Error reading secrets, err=%v", err)
		return nil
	}

	// Encode all k,v pairs
	if s == nil || s.Data == nil {
		return out
	}
	for k, v := range s.Data {
		// value v can be:
		// bool, for JSON booleans
		// float64, for JSON numbers
		// string, for JSON strings
		// []interface{}, for JSON arrays
		// map[string]interface{}, for JSON objects
		// nil for JSON null
		//
		// currently handles string, bool and json.Number
		// TODO handle map[string]interface{} and []interface{}
		r := ""
		if v != nil {
			switch v.(type) {
			case string:
				s, ok := v.(string)
				if !ok {
					fmt.Printf("error converting string")
				}
				r = s
			case json.Number:
				r = string(v.(json.Number))
			case bool:
				if v.(bool) {
					r = "true"
				} else {
					r = "false"
				}
			default:
				fmt.Printf("error reading value at %s, key=%s, type=%T\n", path, k, v)
			}
		}

		e := base64.StdEncoding.EncodeToString([]byte(r))
		out[k] = e
	}

	return out
}

// Write takes in a vault path and base64 encoded data to be written at that path.
func (v *Vault) Write(path string, data map[string]string) error {
	body := make(map[string]interface{})

	// Decode the base64 values
	for k, v := range data {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return err
		}
		body[k] = string(b)
	}

	secret, err := v.c.Logical().Write(path, body)
	if err != nil {
		return err
	}
	if secret == nil {
		return fmt.Errorf("No secret returned when writing to %s", path)
	}
	return nil
}
