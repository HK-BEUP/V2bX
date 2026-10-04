package observer

import "net/netip"

const (
	DialSucceeded uint8 = iota + 1
	DialRefused
	DialTimedOut
	DialCancelled
	DialOtherError
)

// These count completed OS TCP dial attempts, including retries; they are not
// HTTP requests, UDP packets or confirmed attacks. Existing unknown metrics
// stay null and the full-protocol Complete flag remains false.
type DialMetrics struct {
	Credential                      string `json:"credential_digest"`
	IdentityComplete                bool   `json:"identity_complete"`
	Attempts                        int64  `json:"attempts"`
	Succeeded                       int64  `json:"succeeded"`
	Refused                         int64  `json:"refused"`
	TimedOut                        int64  `json:"timed_out"`
	Cancelled                       int64  `json:"cancelled"`
	OtherErrors                     int64  `json:"other_errors"`
	RefusedAttemptsOnMaxPortsTarget int64  `json:"refused_attempts_on_max_ports_target"`
	MaxRefusedTargetPorts           int    `json:"max_refused_target_ports"`
}
type dialTarget struct {
	attempts int64
	ports    map[uint16]struct{}
}

func (o *Observer) ObserveDial(tag, label, address string, port uint16, outcome uint8) {
	if !o.tcpDialMetrics {
		return
	}
	if outcome < DialSucceeded || outcome > DialOtherError {
		o.drop(&o.invalidDrops)
		return
	}
	// A refused target must be the actual resolved IP returned by the OS, not
	// an inferred hostname or a DNS failure. Invalid evidence taints the window.
	if outcome == DialRefused {
		if _, e := netip.ParseAddr(address); e != nil {
			o.drop(&o.invalidDrops)
			return
		}
	}
	o.observeEvent(tag, label, "tcp", address, port, outcome)
}
func (o *Observer) recordDialLocked(w *windowCounts, a *counts, event pendingRequest) {
	if !o.tcpDialMetrics || event.outcome < DialSucceeded || event.outcome > DialOtherError {
		w.lost++
		return
	}
	if a.metrics.TCPDial == nil {
		a.metrics.TCPDial = &DialMetrics{}
	}
	m := a.metrics.TCPDial
	if event.outcome == DialRefused {
		if a.dialTargets == nil {
			a.dialTargets = map[[32]byte]*dialTarget{}
		}
		t := a.dialTargets[event.target]
		delta := 0
		if t == nil {
			delta = 2
		} else if _, known := t.ports[event.port]; !known {
			delta = 1
		}
		edges := o.edges
		if o.next != nil {
			edges += o.next.edges
		}
		if (t == nil && len(a.dialTargets) >= 2048) || (t != nil && len(t.ports) >= 2048 && delta > 0) || edges+delta > 65536 {
			o.capacityDrops.Add(1)
			w.lost++
			return
		}
		if t == nil {
			t = &dialTarget{ports: map[uint16]struct{}{}}
			a.dialTargets[event.target] = t
		}
		w.edges += delta
		t.attempts++
		t.ports[event.port] = struct{}{}
		// The two values describe the SAME target. Independent maxima from
		// different targets must not be combined into fictitious evidence.
		if len(t.ports) > m.MaxRefusedTargetPorts || (len(t.ports) == m.MaxRefusedTargetPorts && t.attempts > m.RefusedAttemptsOnMaxPortsTarget) {
			m.MaxRefusedTargetPorts = len(t.ports)
			m.RefusedAttemptsOnMaxPortsTarget = t.attempts
		}
	}
	m.Attempts++
	w.accepted++
	switch event.outcome {
	case DialSucceeded:
		m.Succeeded++
	case DialRefused:
		m.Refused++
	case DialTimedOut:
		m.TimedOut++
	case DialCancelled:
		m.Cancelled++
	case DialOtherError:
		m.OtherErrors++
	}
}
func RecordDial(tag, label, address string, port uint16, outcome uint8) {
	if o := active.Load(); o != nil {
		o.ObserveDial(tag, label, address, port, outcome)
	}
}
