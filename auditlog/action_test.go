package auditlog

import "testing"

var categories = []struct {
	in  Action
	out string
}{
	{"", ""},
	{"user", "user"},
	{"user.login", "user"},
	{"dev.user.login", "user"},
	{"internal.user.login", "user"},
	{"test.user.login", "user"},
}

func TestActionCategory(t *testing.T) {
	for _, tt := range categories {
		t.Run(string(tt.in), func(t *testing.T) {
			if tt.in.Category() != tt.out {
				t.Errorf("got %q, wanted %q", tt.in.Category(), tt.out)
			}
		})
	}
}

var names = []struct {
	in  Action
	out string
}{
	{"", ""},
	{"user", ""},
	{"user.login", "login"},
	{"dev.user.login", "login"},
	{"internal.user.login", "login"},
	{"test.user.login", "login"},
}

func TestActionName(t *testing.T) {
	for _, tt := range names {
		t.Run(string(tt.in), func(t *testing.T) {
			if tt.in.Name() != tt.out {
				t.Errorf("got %q, wanted %q", tt.in.Name(), tt.out)
			}
		})
	}
}

var environments = []struct {
	in  Action
	out string
}{
	{"", ""},
	{"user", ""},
	{"user.login", ""},
	{"dev.user.login", "dev"},
	{"internal.user.login", "internal"},
	{"test.user.login", "test"},
}

func TestActionEnvironment(t *testing.T) {
	for _, tt := range environments {
		t.Run(string(tt.in), func(t *testing.T) {
			if tt.in.Environment() != tt.out {
				t.Errorf("got %q, wanted %q", tt.in.Environment(), tt.out)
			}
		})
	}
}

var multipleNames = []struct {
	in  Action
	out string
}{
	{"", ""},
	{"user", ""},
	{"user.login", "login"},
	{"user.login.logout", "login"},
	{"dev.user.login", "login"},
	{"internal.user.login", "login"},
	{"test.user.login", "login"},
}

func TestActionNameWithMultipleParts(t *testing.T) {
	for _, tt := range multipleNames {
		t.Run(string(tt.in), func(t *testing.T) {
			if tt.in.Name() != tt.out {
				t.Errorf("got %q, wanted %q", tt.in.Name(), tt.out)
			}
		})
	}
}
