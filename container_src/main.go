package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	widgets := []map[string]interface{}{
		{"id": 1, "name": "Widget A"},
		{"id": 2, "name": "Widget B"},
		{"id": 3, "name": "Widget C"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(widgets)
}

func main() {
	http.HandleFunc("/api/widgets", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
