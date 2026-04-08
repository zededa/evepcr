// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
//
// This file is derived from https://github.com/google/go-attestation (attest/eventlog_workarounds.go).

package attest

import "fmt"

type elWorkaround struct {
	id          string
	affectedPCR int
	apply       func(e *EventLog) error
}

// inject appends one or more new events into the event log.
func inject(e *EventLog, pcr int, items ...string) error {
	for _, data := range items {
		evt := rawEvent{
			data:     []byte(data),
			index:    pcr,
			sequence: e.rawEvents[len(e.rawEvents)-1].sequence + 1,
		}
		for _, alg := range e.Algs {
			hash, err := alg.cryptoHash()
			if err != nil {
				return fmt.Errorf("unknown algorithm ID %x: %v", alg, err)
			}
			h := hash.New()
			h.Write([]byte(data))
			evt.digests = append(evt.digests, Digest{hash: hash, data: h.Sum(nil)})
		}
		e.rawEvents = append(e.rawEvents, evt)
	}
	return nil
}

const (
	ebsInvocation = "Exit Boot Services Invocation"
	ebsSuccess    = "Exit Boot Services Returned with Success"
	ebsFailure    = "Exit Boot Services Returned with Failure"
)

var eventlogWorkarounds = []elWorkaround{
	{
		id:          "EBS Invocation + Success",
		affectedPCR: 5,
		apply: func(e *EventLog) error {
			return inject(e, 5, ebsInvocation, ebsSuccess)
		},
	},
	{
		id:          "EBS Invocation + Failure",
		affectedPCR: 5,
		apply: func(e *EventLog) error {
			return inject(e, 5, ebsInvocation, ebsFailure)
		},
	},
	{
		id:          "EBS Invocation + Failure + Success",
		affectedPCR: 5,
		apply: func(e *EventLog) error {
			return inject(e, 5, ebsInvocation, ebsFailure, ebsSuccess)
		},
	},
}
