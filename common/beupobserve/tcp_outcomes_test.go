package observer

import (
	"encoding/json"
	"fmt"
	"github.com/InazumaV/V2bX/common/beupidentity"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tcpFixture(t *testing.T) (*Observer, *atomic.Int64) {
	t.Helper()
	clock := new(atomic.Int64)
	clock.Store(1800000000)
	o, e := New(Config{Node: "synthetic-jp", IdentityRevision: "synthetic-v1", Bindings: map[string]map[int]string{"a": {2: testSubject}}, Now: func() time.Time { return time.Unix(clock.Load(), 0) }, TCPDialMetrics: true})
	if e != nil {
		t.Fatal(e)
	}
	o.Bind("a", "private-synthetic-label", 2, "synthetic-credential-old")
	return o, clock
}
func TestTCPOutcomesSeparateActualAttemptsFromRequestsAndUnknownMetrics(t *testing.T) {
	o, _ := tcpFixture(t)
	o.Observe("a", "private-synthetic-label", "tcp", "private.example.test", 443)
	for outcome := DialSucceeded; outcome <= DialOtherError; outcome++ {
		o.ObserveDial("a", "private-synthetic-label", "192.0.2.7", 443, outcome)
	}
	r, e := o.Snapshot(time.Unix(1800000060, 0))
	if e != nil || len(r) != 1 || len(r[0].Subjects) != 1 {
		t.Fatal(r, e)
	}
	s := r[0].Subjects[0]
	m := s.Metrics
	d := m.TCPDial
	if !d.IdentityComplete || d.Credential != beupidentity.CredentialDigest("synthetic-credential-old") {
		t.Fatal("missing exact authenticated credential proof")
	}
	if r[0].Version != 2 || r[0].Profile != TCPProfile || r[0].Complete || d == nil || m.ProxyRequests != 1 || m.DistinctTargets != 1 || d.Attempts != 5 || d.Succeeded != 1 || d.Refused != 1 || d.TimedOut != 1 || d.Cancelled != 1 || d.OtherErrors != 1 {
		t.Fatal("mixed metric meanings", r)
	}
	if m.BytesOut != nil || m.BytesIn != nil || m.UDPPackets != nil || m.FailedConnections != nil {
		t.Fatal("unknown broad-protocol metric invented")
	}
	b, _, e := o.Encode(r[0], []byte(strings.Repeat("x", 32)), time.Unix(1800000060, 0))
	if e != nil {
		t.Fatal(e)
	}
	for _, private := range []string{"192.0.2.7", "private.example.test", "private-synthetic-label", "synthetic-credential-old"} {
		if strings.Contains(string(b), private) {
			t.Fatal("private destination/identity leaked")
		}
	}
}

func TestTCPCredentialRotationCannotReassignOldEvidence(t *testing.T) {
	o, clock := tcpFixture(t)
	o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 80, DialRefused)
	o.Bind("a", "new-label", 2, "synthetic-credential-new")
	o.Unbind("a", "private-synthetic-label")
	o.ObserveDial("a", "new-label", "192.0.2.1", 81, DialRefused)
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	d := r[0].Subjects[0].Metrics.TCPDial
	if d.IdentityComplete || d.Credential != "" || d.Attempts != 2 {
		t.Fatal("mixed credentials produced enforceable identity", d)
	}
	clock.Store(1800000060)
	o.ObserveDial("a", "new-label", "192.0.2.1", 82, DialRefused)
	r, _ = o.Snapshot(time.Unix(1800000120, 0))
	d = r[0].Subjects[0].Metrics.TCPDial
	if !d.IdentityComplete || d.Credential != beupidentity.CredentialDigest("synthetic-credential-new") || d.Attempts != 1 {
		t.Fatal("new clean minute did not retain exact identity", d)
	}
}

func TestTCPMissingCredentialProofNeverBecomesCompleteWithinMinute(t *testing.T) {
	o, _ := tcpFixture(t)
	o.Bind("a", "legacy-label", 2)
	o.Observe("a", "legacy-label", "tcp", "192.0.2.1", 80)
	o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 80, DialRefused)
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	d := r[0].Subjects[0].Metrics.TCPDial
	if d.IdentityComplete || d.Credential != "" || d.Attempts != 1 {
		t.Fatal("partial credential proof silently recovered", d)
	}
}

func TestTCPQueuedOutcomeBeforeRebindingNotAssignedToReplacement(t *testing.T) {
	o, _ := tcpFixture(t)
	o.mu.Lock()
	o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 80, DialRefused)
	o.mu.Unlock()
	o.Bind("a", "private-synthetic-label", 2, "synthetic-credential-new")
	o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 81, DialRefused)
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	d := r[0].Subjects[0].Metrics.TCPDial
	if d.Attempts != 1 || r[0].Quality.DroppedRequests != 1 || !r[0].Quality.PartialWindow {
		t.Fatal("queued old proof reassigned", r)
	}
}

func TestTCPWindowManifestClosesAllBatchesIncludingEmpty(t *testing.T) {
	bindings := map[int]string{}
	for uid := 1; uid <= 201; uid++ {
		bindings[uid] = fmt.Sprintf("%032x", uid)
	}
	o, e := New(Config{Node: "synthetic-jp", IdentityRevision: "synthetic-v1", Bindings: map[string]map[int]string{"a": bindings}, Now: func() time.Time { return time.Unix(1800000000, 0) }, TCPDialMetrics: true})
	if e != nil {
		t.Fatal(e)
	}
	for uid := 1; uid <= 201; uid++ {
		label := fmt.Sprintf("label-%d", uid)
		o.Bind("a", label, uid, "synthetic")
		o.ObserveDial("a", label, "192.0.2.1", 80, DialRefused)
	}
	r, e := o.Snapshot(time.Unix(1800000060, 0))
	if e != nil || len(r) != 2 {
		t.Fatal(e, len(r))
	}
	for i, report := range r {
		m := report.TCPWindow
		if m == nil || m.Index != i || m.Batches != 2 || m.Subjects != 201 || m.ID != r[0].TCPWindow.ID {
			t.Fatal("inconsistent signed window", report)
		}
		if _, _, e = o.Encode(report, []byte(strings.Repeat("x", 32)), time.Unix(1800000060, 0)); e != nil {
			t.Fatal(e)
		}
	}
	r, e = o.Snapshot(time.Unix(1800000120, 0))
	if e != nil || len(r) != 1 || r[0].TCPWindow.Batches != 1 || r[0].TCPWindow.Subjects != 0 || len(r[0].Subjects) != 0 {
		t.Fatal("empty heartbeat missing manifest", r, e)
	}
}
func TestTCPRefusalEvidenceUsesSameTargetAndUniquePorts(t *testing.T) {
	o, _ := tcpFixture(t)
	for n := 0; n < 1000; n++ {
		o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 443, DialRefused)
	}
	for port := 1; port <= 128; port++ {
		o.ObserveDial("a", "private-synthetic-label", "192.0.2.2", uint16(port), DialRefused)
	}
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	d := r[0].Subjects[0].Metrics.TCPDial
	if d.Refused != 1128 || d.MaxRefusedTargetPorts != 128 || d.RefusedAttemptsOnMaxPortsTarget != 128 {
		t.Fatal("combined independent maxima", d)
	}
}
func TestTCPRefusedHostnameIsNotTreatedAsResolvedIP(t *testing.T) {
	o, _ := tcpFixture(t)
	o.ObserveDial("a", "private-synthetic-label", "unresolved.example.test", 443, DialRefused)
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	if len(r[0].Subjects) != 0 || r[0].Quality.DroppedRequests != 1 || !r[0].Quality.PartialWindow {
		t.Fatal("unresolved target accepted", r)
	}
}
func TestTCPDisabledPreservesV1AndDoesNotAddZeroMetrics(t *testing.T) {
	o, _ := sample(t)
	o.ObserveDial("test-inbound", "PRIVATE-TEST-CREDENTIAL", "192.0.2.1", 443, DialRefused)
	o.Observe("test-inbound", "PRIVATE-TEST-CREDENTIAL", "tcp", "example.test", 443)
	r := snapshot(t, o, 1800000060)
	b, _ := json.Marshal(r)
	if r[0].Version != 1 || r[0].Profile != Profile || strings.Contains(string(b), "tcp_dial") {
		t.Fatal("legacy wire format changed")
	}
}
func TestTCPBufferedBoundaryAndCapacityLossRemainVisible(t *testing.T) {
	o, clock := tcpFixture(t)
	o.mu.Lock()
	for n := 0; n < pendingCapacity+1; n++ {
		o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 443, DialSucceeded)
	}
	o.mu.Unlock()
	r, _ := o.Snapshot(time.Unix(1800000060, 0))
	if r[0].Subjects[0].Metrics.TCPDial.Attempts != pendingCapacity || r[0].Quality.DroppedRequests != 1 || !r[0].Quality.PartialWindow {
		t.Fatal("outcome overflow hidden")
	}
	clock.Store(1800000060)
	o.ObserveDial("a", "private-synthetic-label", "192.0.2.1", 80, DialRefused)
	r, _ = o.Snapshot(time.Unix(1800000120, 0))
	if r[0].Subjects[0].Metrics.TCPDial.Attempts != 1 || !r[0].Quality.PartialWindow {
		t.Fatal("shared boundary loss misrepresented")
	}
}
