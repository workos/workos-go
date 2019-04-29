package auditlog

import (
	"encoding/json"
	"testing"
)

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
	event, _ := NewEventWithMetadata("user.login", Create, map[string]interface{}{
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

	event.AddMetadata(map[string]interface{}{
		"key": "value",
	})

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
		event.AddMetadata(map[string]interface{}{
			string(i): string(i),
		})
	}

	err := event.AddMetadata(map[string]interface{}{
		"key": "value",
	})

	if err != ErrMaximumMetadataProperties {
		t.Error("event.Metadata should not have added entries for key/value")
	}
}

func TestEventPublishMergesGlobalMetadata(t *testing.T) {
	SetMetadata(map[string]interface{}{
		"environment": "testing",
	})

	event := NewEvent("user.login", Create)

	if event.Metadata["environment"] == "testing" {
		t.Errorf("expected event to not have any metadata for environment, got %q", event.Metadata["environment"])
	}

	event.Publish()

	if event.Metadata["environment"] != "testing" {
		t.Errorf("expected event to have metadata for environment, got %q", event.Metadata["environment"])
	}
}
func TestEventGlobalMetadataOverridesLocalMetadata(t *testing.T) {
	SetMetadata(map[string]interface{}{
		"environment": "testing",
	})

	event, err := NewEventWithMetadata("user.login", Create, map[string]interface{}{
		"environment": "production",
	})

	if err != nil {
		t.Error(err)
	}

	if event.Metadata["environment"] != "production" {
		t.Errorf("expected event to have metadata for environment set to production, got %q", event.Metadata)
	}

	event.Publish()

	if event.Metadata["environment"] != "testing" {
		t.Errorf("expected event to have had metadata overrwritten for environment, got %q", event.Metadata["environment"])
	}
}

type fakeUser struct {
}

func (u fakeUser) ToAuditableName() string {
	return "user"
}

func (u fakeUser) ToAuditableID() string {
	return "user_1"
}
func TestEventAddingMetadataThatImplementsAuditable(t *testing.T) {
	user := fakeUser{}
	event, _ := NewEventWithMetadata("user.login", Create, map[string]interface{}{
		"user": user,
	})

	if event.Metadata["user"] != nil {
		t.Errorf("expected event to not have key at user, got: %q", event.Metadata)
	}

	if event.Metadata["user_name"] != user.ToAuditableName() {
		t.Errorf("expected metadata for `user_name` to be %q, got: %q", user.ToAuditableName(), event.Metadata["user_name"])
	}

	if event.Metadata["user_id"] != user.ToAuditableID() {
		t.Errorf("expected metadata for `user_id` to be %q, got: %q", user.ToAuditableID(), event.Metadata["user_id"])
	}
}

func TestEventSerializesToJSONAndBack(t *testing.T) {
	user := fakeUser{}
	source, _ := NewEventWithMetadata("user.login", Create, map[string]interface{}{
		"user": user,
	})

	source.SetGroup(user)
	source.SetActor(user)
	source.SetTarget(user)
	source.SetLocation("1.1.1.1")

	body, err := json.Marshal(source)
	if err != nil {
		t.Error(err)
	}

	event := Event{}
	err = json.Unmarshal(body, &event)
	if err != nil {
		t.Error(err)
	}

	if event.Group != "user_1" {
		t.Errorf("expected event group to be %q, got %q", source.Group, event.Group)
	}

	if event.Action != "user.login" {
		t.Errorf("expected event action to be %q, got %q", source.Action, event.Action)
	}

	if event.ActionType != "C" {
		t.Errorf("expected event action_type to be %q, got %q", source.ActionType, event.ActionType)
	}

	if event.ActorName != "user" {
		t.Errorf("expected event actor_name to be %q, got %q", source.ActorName, event.ActorName)
	}

	if event.ActorID != "user_1" {
		t.Errorf("expected event actor_id to be %q, got %q", source.ActorID, event.ActorID)
	}

	if event.TargetName != "user" {
		t.Errorf("expected event target_name to be %q, got %q", source.TargetName, event.TargetName)
	}

	if event.TargetID != "user_1" {
		t.Errorf("expected event target_id to be %q, got %q", source.TargetID, event.TargetID)
	}

	if event.OccuredAt != source.OccuredAt {
		t.Errorf("expected event occured_at to be %q, got %q", source.OccuredAt, event.OccuredAt)
	}

	if event.Location != "1.1.1.1" {
		t.Errorf("expected event location to be %q, got %q", source.Location, event.Location)
	}

	if event.Metadata["user_name"] != "user" {
		t.Errorf("expected event metadata user_name to be %q, got %q", source.Metadata["user_name"], event.Metadata["user_name"])
	}

	if event.Metadata["user_id"] != "user_1" {
		t.Errorf("expected event metadata user_id to be %q, got %q", source.Metadata["user_name"], event.Metadata["user_name"])
	}
}
