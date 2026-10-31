package lib

import "net/http"

func init() {
	http.HandleFunc("/dummy-value-do-not-leak-9f3a2c", nil)
}
