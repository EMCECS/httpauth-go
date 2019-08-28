// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"fmt"
	"net/http"
	"time"
)

func ExampleNewPolicy() {
	const port = ":8000"

	// Create an authorization policy that uses the NTLM authorization
	// scheme.  The credientials will be considered valid if the password
	// is simply the username repeated twice.
	auth := NewPolicy(func(name string) string {
		return name + name
	}, "EXAMPLE", nil)
	// The request handler for the restricted portion of the website.
	http.HandleFunc("/example/", func(w http.ResponseWriter, r *http.Request) {
		// Check if the client is authorized
		username := auth.Authorize(r)
		if username == "" {
			// Oops!  Access denied.
			auth.NotifyAuthRequired(w, r)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
	})
	// The request handle for the unrestricted portion of the website.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>The index</h1><p>...</p></body></html>")
	})

	// This is just an example.  Run the HTTP server for ten seconds and then quit.
	go http.ListenAndServe(port, nil)
	time.Sleep(10 * time.Second)
}
