// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package main

import (
	"log"
	"net/http"

	"phobia.cloud/api/handler"
)

func main() {
	http.HandleFunc("/challenge", handler.Challenge)
	http.HandleFunc("/login", handler.Login)

	log.Fatal(http.ListenAndServe(":5050", nil))
}
