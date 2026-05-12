package main

// Static-analysis guard for the "forwarded the envelope, not the inner
// payload" bug class. See the read-receipt regression that landed in
// 789d7ac (2026-05-12): HandleIncomingReadReceipt decrypted the
// EncryptedPeerEnvelope but then PublishToApp'd the raw envelope bytes
// instead of dec.InnerPayload. App subscribers got JSON they couldn't
// parse and the UI never updated.
//
// The invariant is simple: any function that calls
// decryptIncomingPeerEnvelope(_, X) MUST NOT later call PublishToApp
// passing X. The app has no shared secret and can't unwrap envelopes.
// Pass dec.InnerPayload, or re-marshal an inner struct.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPeerEnvelopeNotForwardedToApp parses every .go file in this
// package and fails if it finds a function where the same identifier
// used as the second argument to decryptIncomingPeerEnvelope is later
// passed as the last argument to PublishToApp. That pattern is the
// "envelope leak" bug.
//
// The check is intentionally syntactic — it does NOT chase aliases or
// fields, so a handler that renames `msg.Payload` into `raw` and forwards
// `raw` can still slip through. But the common shape (PublishToApp(_,_, data)
// where `data` was the envelope arg) is exactly what we want to forbid.
func TestPeerEnvelopeNotForwardedToApp(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	var leaks []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			// Find the envelope-input identifier name within this function,
			// if any. We treat the SECOND argument to
			// decryptIncomingPeerEnvelope as the "envelope bytes" source.
			envelopeArg := ""
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if !isCallNamed(call, "decryptIncomingPeerEnvelope") {
					return true
				}
				if len(call.Args) < 2 {
					return true
				}
				if id := identName(call.Args[1]); id != "" {
					envelopeArg = id
				}
				return true
			})
			if envelopeArg == "" {
				return true
			}
			// Now walk PublishToApp call sites in the same function and
			// flag any whose last argument is the same envelope identifier.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if !isMethodNamed(call, "PublishToApp") {
					return true
				}
				if len(call.Args) == 0 {
					return true
				}
				last := call.Args[len(call.Args)-1]
				if identName(last) == envelopeArg {
					pos := fset.Position(call.Pos())
					leaks = append(leaks, pos.String()+" in "+fn.Name.Name+
						": PublishToApp(..., "+envelopeArg+") — `"+envelopeArg+
						"` is the envelope bytes passed to decryptIncomingPeerEnvelope. "+
						"Pass dec.InnerPayload or re-marshal an inner struct instead.")
				}
				return true
			})
			return true
		})
	}

	if len(leaks) > 0 {
		t.Errorf("encrypted-envelope-to-app leaks found:\n  %s", strings.Join(leaks, "\n  "))
	}
}

// identName returns the bare identifier name for an expression, or ""
// if the expression isn't a plain identifier. We deliberately don't
// follow x.y / selector chains — see the test's docstring on scope.
func identName(e ast.Expr) string {
	id, ok := e.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// isCallNamed reports whether c is a bare function call to the given
// name (decryptIncomingPeerEnvelope, etc.).
func isCallNamed(c *ast.CallExpr, name string) bool {
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == name
}

// isMethodNamed reports whether c is a method call like receiver.Name(...)
// regardless of the receiver expression. Used for PublishToApp, which is
// always called as h.publisher.PublishToApp / mh.publisher.PublishToApp.
func isMethodNamed(c *ast.CallExpr, name string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}
