//go:build !linux

package main

func stateChecks(string) []doctorCheck {
	return []doctorCheck{{"state_permissions", "unavailable", "daemon filesystem checks require Linux", "run doctor on the supported Linux daemon host"}, {"state_space", "not_checked", "daemon filesystem checks require Linux", ""}}
}

func capabilityCheck(string) doctorCheck {
	return doctorCheck{"capabilities", "unavailable", "Linux capabilities are unavailable on this host", "run doctor on the supported Linux executor host"}
}
