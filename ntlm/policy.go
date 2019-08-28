// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"bitbucket.org/rj/httpauth-go"
	"encoding/base64"
	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/ntlm"
	"io"
	"log"
	"net/http"
	"strings"
)

// The constant StatusUnauthorizedHtml contains the response body written
// by default when a request cannot be authorized.  This can be overridden
// by updating the field WriterUnauthorized in the authentication policy.
const (
	StatusUnauthorizedHTML string = "<html><body><h1>Unauthorized</h1></body></html>"
)

//var (
//	challenge = [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
//)

// A Policy is a HTTP authentication policy for authenticating users using the NTLM authentication scheme.
type Policy struct {
	// LogAuthenticationFailure provides a function or closure that logs authentication errors
	LogAuthenticationFailure func(msg string)
	// WriterUnauthorized provides a function or closure that writes out the HTML portion of a unauthorized access response.
	WriterUnauthorized httpauth.HtmlWriter

	// Credentials
	credentials *sspi.Credentials
	// This is initialized uniquely for each policy.
	// TODO:  Need to handle simultaneous connections
	context *ntlm.ServerContext
}

func defaultLogAuthenticationFailure(msg string) {
	log.Println("Error: NTLM authentication:", msg)
}

func defaultHTMLWriter(w io.Writer, _ *http.Request) {
	w.Write([]byte(StatusUnauthorizedHTML))
}

// NewPolicy creates a new authentication policy that uses the NTLM authentication scheme.
//
// The value of writer can be nil.  In this case, the policy will use
// a default behaviour that writes a simple error message for the
// response body.
func NewPolicy(target string, writer httpauth.HtmlWriter) (*Policy, error) {
	// Fill in default policy for writing HTML when authorization is denied.
	if writer == nil {
		writer = defaultHTMLWriter
	}
	// Use SSPI to get an authorization context
	credentials, err := ntlm.AcquireServerCredentials()
	if err != nil {
		return nil, err
	}

	// Create the policy struct
	ret := &Policy{
		LogAuthenticationFailure: defaultLogAuthenticationFailure,
		WriterUnauthorized:       writer,
		credentials:              credentials}
	return ret, nil
}

// Authorize retrieves the credientials from the HTTP request, and
// returns the username only if the credientials could be validated.
// If the return value is blank, then the credentials are missing,
// invalid, or a system error prevented verification.
func (a *Policy) Authorize(r *http.Request) string {
	// There are multiple message exchanges in this protocal.  Since
	// we don't have a structure to maintain the session, we need to
	// reverse engineer the state.

	// Do we have a NLTM token?  If not, the client has not provided the
	// necessary credientials.
	token := r.Header.Get("Authorization")
	if !strings.HasPrefix(token, "NTLM ") {
		return ""
	}
	// Decode the NTLM token.  Verify that it has the correct signature,
	// and that it is the correct type
	data, err := base64.StdEncoding.DecodeString(token[5:])
	if err != nil {
		a.LogAuthenticationFailure(err.Error())
		return ""
	}
	if !checkNTLMMessageSignature(data) {
		a.LogAuthenticationFailure("malformed NTLM message, incorrect signature")
		return ""
	}
	if msgType := getNTLMMessageType(data); msgType == 0x1000000 {
		// Client is responding to initial message.  We can't proceed
		// until the client responds with the type 3 message.
		return ""
	} else if msgType != 0x3000000 {
		// Client ought to response with either a type1 or type3 message.  We
		// just checked for a type 1, so if it isn't a type 3, the client has
		// made an error.
		a.LogAuthenticationFailure("malformed NTLM message, unexpected type")
		return ""
	}

	// Take the raw bytes, and extract the message
	err = a.context.Update(data)
	if err != nil {
		a.LogAuthenticationFailure(err.Error())
		return ""
	}

	var msg type3Message
	err = msg.Decode(data)
	if err != nil {
		a.LogAuthenticationFailure(err.Error())
		return ""
	}

	return ConvertString(msg.Flags, msg.UserName)
}

// NotifyAuthRequired adds the headers to the HTTP response to
// inform the client of the failed authorization, and which scheme
// must be used to gain authentication.
func (a *Policy) NotifyAuthRequired(w http.ResponseWriter, r *http.Request) {
	// There are multiple message exchanges in this protocal.  Since
	// we don't have a structure to maintain the session, we need to
	// reverse engineer the state.

	// NTLM negotiation has started?
	authtoken := r.Header.Get("Authorization")
	if strings.HasPrefix(authtoken, "NTLM ") {
		token, err := a.handleNegotiation(w, authtoken)
		if err == nil {
			// According to the standard, we should close the connection afterwards
			r.Close = true
			// Set the header with the NTLM type 2 message
			w.Header().Set("WWW-Authenticate", token)
			w.WriteHeader(http.StatusUnauthorized)
			a.WriterUnauthorized(w, r)
			return
		}
	}

	// No NTLM message.  We are responding to initial contact,
	// so we respond with a header to indicate that we would like
	// to see NTLM authentication.
	w.Header().Set("WWW-Authenticate", "NTLM")
	w.WriteHeader(http.StatusUnauthorized)
	a.WriterUnauthorized(w, r)
}

func (a *Policy) handleNegotiation(w http.ResponseWriter, token string) (string, error) {
	// We should have a type one message
	data, err := base64.StdEncoding.DecodeString(token[5:])
	if err != nil {
		a.LogAuthenticationFailure(err.Error())
		return "", err
	}

	context, msg, err := ntlm.NewServerContext(a.credentials, data)
	if err != nil {
		return "", err
	}
	a.context = context

	return "NTLM " + base64.StdEncoding.EncodeToString(msg), nil
}
