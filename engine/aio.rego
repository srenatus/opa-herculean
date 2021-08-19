package main

# Returns the map of signature identifiers to signature metadata.
# {
#   "TRC-2": {
#     "id": "TRC-2",
#     "version": "0.1.0",
#     "name": "Anti-Debugging",
#     "description": "Process uses anti-debugging technique to block debugger",
#     "tags": ["linux", "container"],
#     "properties": {
#       "Severity": "3",
#       "MITRE ATT&CK": "Defense Evasion: Execution Guardrails"
#     }
#   },
#   "TRC-3": {}
# }
__rego_metadoc_all__[id] = resp {
	some i
		resp := data.tracee[i].__rego_metadoc__
		id := resp.id
}

# Returns the map of signature identifiers to signature selected events.
tracee_selected_events_all[id] = resp {
	some i
		resp := data.tracee[i].tracee_selected_events
		metadata := data.tracee[i].__rego_metadoc__
		id := metadata.id
}

# Returns the map of signature identifiers to values matching the input event.
tracee_match_all[id] = resp {
	some i
		# TODO Try adding event selector
		# some i, j
		#   data.tracee[i].tracee_selected_events[j].name == input.eventName
		resp := data.tracee[i].tracee_match
		metadata := data.tracee[i].__rego_metadoc__
		id := metadata.id
}
