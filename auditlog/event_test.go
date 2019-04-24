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

func TestNewEvent(t *testing.T) {
	event := NewEvent("user.login", Create)
	if event.Action != "user.login" {
		t.Errorf("got %q, wanted user.login", event.Action)
	}

	if event.ActionType != Create {
		t.Errorf("got %q, wanted %q", event.ActionType, Create)
	}

	if event.Location == "" {
		t.Error("event.Location should not be empty")
	}
}

func TestNewEventWithMetadata(t *testing.T) {
	event := NewEventWithMetadata("user.login", Create, map[string]string{
		"user_agent": "Mozilla",
	})

	if len(event.Metadata) != 1 {
		t.Error("event.Metadata should contain one entry")
	}

	if event.Metadata["user_agent"] != "Mozilla" {
		t.Error("event.Metadata should contain one entry")
	}
}

func TestEventAddingMetadata(t *testing.T) {
	event := NewEvent("user.login", Create)
	if len(event.Metadata) != 0 {
		t.Error("event.Metadata should be empty")
	}

	event.AddMetadata("key", "value")

	if len(event.Metadata) != 1 {
		t.Error("event.Metadata should contain key/value")
	}

	if event.Metadata["key"] != "value" {
		t.Error("event.Metadata[key] should equal value")
	}
}

func TestEventAddingMetadataLimit(t *testing.T) {
	event := NewEvent("user.login", Create)

	buffer := make([]int, 500)
	for i := range buffer {
		event.AddMetadata(string(i), string(i))
	}

	event.AddMetadata("key", "value")

	if event.Metadata["key"] != "" {
		t.Error("event.Metadata should not have added entries for key/value")
	}

	if len(event.Metadata) != 500 {
		t.Error("event.Metadata should not contain over 500 entries")
	}
}
