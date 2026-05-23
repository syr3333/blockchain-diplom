package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

var cfg AppConfig

type AppConfig struct {
	Port                string
	EthereumRPC         string
	FactRegistryAddress string
	VerifierID          string
	VerifierIDHash      string
}

func main() {
	_ = godotenv.Load()

	cfg = AppConfig{
		Port:                getEnv("PORT", "8080"),
		EthereumRPC:         getEnv("ETHEREUM_RPC_URL", "http://127.0.0.1:8545"),
		FactRegistryAddress: getEnv("FACT_REGISTRY_ADDRESS", ""),
		VerifierID:          getEnv("VERIFIER_ID", "did:web:shop.example.com"),
		VerifierIDHash:      getEnv("VERIFIER_ID_HASH", ""),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/lookup", handleLookupFact)
	mux.HandleFunc("/api/config", handleConfig)

	frontendDir := getEnv("FRONTEND_DIR", "../frontend")
	mux.Handle("/", http.FileServer(http.Dir(frontendDir)))

	handler := corsMiddleware(mux)

	fmt.Printf("Verifier backend on :%s\n", cfg.Port)
	fmt.Printf("  FactRegistry: %s\n", cfg.FactRegistryAddress)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"verifier_id":           cfg.VerifierID,
		"verifier_id_hash":      cfg.VerifierIDHash,
		"fact_registry_address": cfg.FactRegistryAddress,
	})
}

func handleLookupFact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	subjectTag := r.URL.Query().Get("subject_tag")
	factTypeHash := r.URL.Query().Get("fact_type_hash")
	verifierIDHash := r.URL.Query().Get("verifier_id_hash")

	if subjectTag == "" || factTypeHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_tag and fact_type_hash required"})
		return
	}
	if verifierIDHash == "" {
		verifierIDHash = cfg.VerifierIDHash
	}

	if cfg.FactRegistryAddress == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service not configured"})
		return
	}

	fact, err := lookupFactOnChain(cfg.EthereumRPC, cfg.FactRegistryAddress, verifierIDHash, subjectTag, factTypeHash)
	if err != nil {
		log.Printf("lookup error: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"exists": false,
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, fact)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}
