package beuptransfer

// Reservations are durable capacity promises, not admission fences. They have
// no local timeout: the panel may already have paused the source while a drain
// command is delayed. Only an explicit reconciled retirement can release one.
const maxDrains = 1000

func validateReservations(s journal) error {
	if len(s.Drains)+len(s.Reservations) > maxDrains {
		return ErrCoverage
	}
	seen := map[Identity]bool{}
	for _, d := range s.Drains {
		if seen[d.Request.Identity] {
			return ErrCoverage
		}
		seen[d.Request.Identity] = true
	}
	for id, r := range s.Reservations {
		if !validRequest(r) || id != r.ID || seen[r.Identity] {
			return ErrCoverage
		}
		if _, exists := s.Drains[id]; exists {
			return ErrCoverage
		}
		seen[r.Identity] = true
	}
	return nil
}

// Caller holds the outbox lock. Both direct drains and probes count promised
// slots, so a later request cannot consume capacity promised to an earlier one.
func (o *Outbox) canReserve(r DrainRequest) error {
	if !validRequest(r) {
		return ErrCoverage
	}
	if old, ok := o.state.Drains[r.ID]; ok {
		if old.Request != r {
			return ErrCoverage
		}
		return nil
	}
	if old, ok := o.state.Reservations[r.ID]; ok {
		if old != r {
			return ErrCoverage
		}
		return nil
	}
	if len(o.state.Drains)+len(o.state.Reservations) >= maxDrains {
		return ErrCoverage
	}
	for _, old := range o.state.Drains {
		if old.Request.Identity == r.Identity {
			return ErrCoverage
		}
	}
	for _, old := range o.state.Reservations {
		if old.Identity == r.Identity {
			return ErrCoverage
		}
	}
	return nil
}

func (o *Outbox) probeReady(r DrainRequest) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned {
		return ErrUncertain
	}
	if err := o.canReserve(r); err != nil {
		return err
	}
	s := clone(o.state)
	if _, draining := s.Drains[r.ID]; !draining {
		if s.Reservations == nil {
			s.Reservations = map[string]DrainRequest{}
		}
		s.Reservations[r.ID] = r
	}
	// Save before reporting capability, including idempotent probes. An uncertain
	// disk write must never be followed by a positive response.
	return o.save(s)
}
