package eventlog

import "github.com/salehkreiner/netherchat/tui/client"

// Mapper turns the client core's high-level events into the structured event
// stream. It maintains a small member directory (id → name + fingerprint) so it
// can attribute messages and leaves by key fingerprint. A Mapper is a passive
// observer: it never marks anyone SAS-verified (verified is always false), and it
// emits metadata only — message bodies appear only when includeBodies is set.
type Mapper struct {
	room          string
	includeBodies bool
	members       map[string]member
}

type member struct {
	name string
	fpr  string
}

// NewMapper returns a Mapper for a room.
func NewMapper(room string, includeBodies bool) *Mapper {
	return &Mapper{room: room, includeBodies: includeBodies, members: map[string]member{}}
}

// Map converts one client event into zero or more stream events. Events with no
// stream representation (server/webhook plaintext, invite/break-glass replies,
// ttl control, our own echoes) return nil.
func (m *Mapper) Map(ev client.Event) []Event {
	switch e := ev.(type) {
	case client.EvConnected:
		out := make([]Event, 0, len(e.Members))
		for _, mem := range e.Members {
			m.members[mem.ID] = member{mem.Name, mem.Fingerprint}
			out = append(out, Join(m.room, mem.Name, mem.Fingerprint, false))
		}
		return out

	case client.EvMemberJoined:
		m.members[e.ID] = member{e.Name, e.Fingerprint}
		return []Event{Join(m.room, e.Name, e.Fingerprint, false)}

	case client.EvMemberLeft:
		mem := m.members[e.ID]
		delete(m.members, e.ID)
		name := e.Name
		if name == "" {
			name = mem.name
		}
		return []Event{Leave(m.room, name, mem.fpr)}

	case client.EvMessage:
		if e.Self {
			return nil
		}
		return []Event{Message(m.room, e.FromName, m.members[e.FromID].fpr, e.Signed, false, e.Text, m.includeBodies)}

	case client.EvKeyReady:
		return []Event{KeyReady(m.room, e.Epoch)}

	case client.EvRouteFired:
		// room is the SPAWNED incident room, not the intake room we are tailing.
		return []Event{RouteFired(e.Room, e.TriggerRule, e.Invitees, e.TTLSeconds)}

	case client.EvAck:
		return []Event{Ack(m.room, e.Actor, e.Fpr, e.Tag, e.Quorum)}

	case client.EvHandoff:
		return []Event{Handoff(m.room, e.FromName, e.FromFpr, e.ToName, e.ToFpr)}

	case client.EvActionRequest: // Two-Person Rule (§1.3)
		return []Event{ActionRequest(m.room, e.RequesterName, e.RequesterFpr, e.Action, e.RequestID, e.QuorumNeeded, e.ExpiresUnix)}

	case client.EvActionApproval:
		return []Event{ActionApproval(m.room, e.ApproverName, e.ApproverFpr, e.RequestID, e.Count, e.Needed)}

	case client.EvActionExecuted:
		return []Event{ActionExecuted(m.room, e.RequesterName, e.RequesterFpr, e.RequestID, e.Action, e.Quorum)}

	case client.EvActionVetoed:
		return []Event{ActionVetoed(m.room, e.VetoerName, e.VetoerFpr, e.RequestID, e.Action, e.Reason)}

	case client.EvActionExpired:
		return []Event{ActionExpired(m.room, e.RequestID, e.Action, e.ApprovalsReceived, e.QuorumNeeded)}

	case client.EvControl:
		switch e.Action {
		case "vanish": // protocol.ActionVanish
			return []Event{Vanish(m.room, e.ByName, m.fprByName(e.ByName))}
		case "scuttle": // protocol.ActionScuttle — the dead-man's switch fired (§1.6)
			return []Event{Scuttle(m.room, e.Reason)}
		case "beacon_set": // protocol.ActionBeaconSet (§1.2)
			return []Event{BeaconSet(m.room, e.ByName, m.fprByName(e.ByName), e.TTLSeconds)}
		case "beacon_cleared": // protocol.ActionBeaconCleared (§1.2)
			return []Event{BeaconCleared(m.room, e.ByName, m.fprByName(e.ByName))}
		}
		return nil // ttl / scuttle_arm are not part of the v1 event schema

	case client.EvExecRequest:
		if e.Self {
			return nil
		}
		return []Event{ExecRequest(m.room, e.FromName, e.FromFingerprint, e.Cmd, nil)}

	case client.EvExecResult:
		return []Event{ExecResult(m.room, e.FromName, e.FromFingerprint, e.Cmd, e.Allowed, e.ExitCode)}

	case client.EvFileOffer:
		return []Event{FileOffer(m.room, e.From, e.Fpr, e.Filename, e.Size, e.TransferID)}

	case client.EvFileComplete:
		// fpr best-effort from the member directory (the complete event carries the
		// display name; the offer carried the fingerprint).
		return []Event{FileComplete(m.room, e.From, m.fprByName(e.From), e.Filename, e.Size, e.TransferID, e.OK)}

	case client.EvStreamUpdate:
		if e.Self {
			return nil
		}
		return []Event{StreamUpdate(m.room, e.From, e.Fpr, e.StreamID)}

	case client.EvStreamEnd:
		return []Event{StreamEnd(m.room, e.StreamID, e.Reason)}

	case client.EvError:
		return []Event{ErrorEvent(m.room, e.Err.Error())}

	case client.EvDisconnected:
		msg := "connection closed"
		if e.Err != nil {
			msg = e.Err.Error()
		}
		return []Event{Disconnect(m.room, msg)}
	}
	return nil
}

// fprByName resolves a fingerprint from a display name (best effort; names are
// not unique). Used for vanish, whose control frame carries only a name.
func (m *Mapper) fprByName(name string) string {
	for _, mem := range m.members {
		if mem.name == name {
			return mem.fpr
		}
	}
	return ""
}
