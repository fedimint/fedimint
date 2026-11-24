package chainreg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
)

// Exercise the actual capability check, including its older RPC fallback paths.
func TestBackendSupportsTaprootRPCCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		blockchain string
		deployment string
		rpcError   bool
		btcd       bool
		malformed  bool
		want       bool
	}{
		{name: "core32", deployment: `{"script_flags":["P2SH","TAPROOT"]}`, want: true},
		{name: "absent flags", deployment: `{}`},
		{name: "empty flags", deployment: `{"script_flags":[]}`},
		{name: "null flags", deployment: `{"script_flags":null}`},
		{name: "unrelated flags", deployment: `{"script_flags":["P2SH","WITNESS"]}`},
		{name: "case sensitive", deployment: `{"script_flags":["taproot"]}`},
		{name: "exact flag", deployment: `{"script_flags":["NOT_TAPROOT"]}`},
		{name: "legacy deployment", deployment: `{"deployments":{"taproot":{"active":true}}}`, want: true},
		{name: "legacy presence semantics", deployment: `{"deployments":{"taproot":{"active":false}}}`, want: true},
		{name: "legacy with empty flags", deployment: `{"deployments":{"taproot":{}},"script_flags":[]}`, want: true},
		{name: "flag with unrelated deployment", deployment: `{"deployments":{"testdummy":{}},"script_flags":["TAPROOT"]}`, want: true},
		{name: "both", deployment: `{"deployments":{"taproot":{}},"script_flags":["TAPROOT"]}`, want: true},
		{name: "malformed flags", deployment: `{"script_flags":42}`},
		{name: "malformed deployment", deployment: `{"deployments":42}`},
		{name: "malformed with flag", deployment: `{"deployments":42,"script_flags":["TAPROOT"]}`},
		{name: "malformed JSON response", malformed: true},
		{name: "rpc error", rpcError: true},
		{name: "legacy blockchain", blockchain: `{"softforks":{"taproot":{"type":"bip9","active":true}}}`, rpcError: true, want: true},
		{name: "legacy btcd", blockchain: `{"bip9_softforks":{"taproot":{}}}`, btcd: true, rpcError: true, want: true},
		{name: "legacy precedence", blockchain: `{"softforks":{"taproot":{"active":false}}}`, malformed: true, want: true},
		{name: "blockchain error fallback", blockchain: "error", deployment: `{"script_flags":["TAPROOT"]}`, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Method string          `json:"method"`
					ID     json.RawMessage `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode RPC request: %v", err)
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				result := json.RawMessage(`{}`)
				var rpcError interface{}
				switch request.Method {
				case "getinfo":
					if test.btcd {
						result = json.RawMessage(`{"version":240000}`)
					} else {
						rpcError = map[string]interface{}{"code": -32601, "message": "unsupported"}
					}
				case "getnetworkinfo":
					result = json.RawMessage(`{"subversion":"/Satoshi:32.1.0/"}`)
				case "getblockchaininfo":
					if test.blockchain == "error" {
						rpcError = map[string]interface{}{"code": -32601, "message": "unsupported"}
					} else if test.blockchain != "" {
						result = json.RawMessage(test.blockchain)
					}
				case "getdeploymentinfo":
					if test.malformed {
						w.Header().Set("Content-Type", "application/json")
						if _, err := w.Write([]byte(`{`)); err != nil {
							t.Errorf("write malformed RPC response: %v", err)
						}
						return
					}
					if test.rpcError {
						rpcError = map[string]interface{}{"code": -32601, "message": "unsupported"}
					} else {
						result = json.RawMessage(test.deployment)
					}
				default:
					t.Errorf("unexpected RPC method %q", request.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"result": result, "error": rpcError, "id": request.ID,
				}); err != nil {
					t.Errorf("encode RPC response: %v", err)
				}
			}))
			defer server.Close()

			client, err := rpcclient.New(&rpcclient.ConnConfig{
				Host:         strings.TrimPrefix(server.URL, "http://"),
				User:         "test",
				Pass:         "test",
				HTTPPostMode: true,
				DisableTLS:   true,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Shutdown()

			if got := backendSupportsTaproot(client); got != test.want {
				t.Errorf("backendSupportsTaproot = %v, want %v", got, test.want)
			}
		})
	}
}
