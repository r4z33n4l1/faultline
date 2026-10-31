package main

import "net/http"

func main() {
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {})
}
