package rules

func containsAll(values []string, wants ...string) bool {
	for _, want := range wants {
		found := false
		for _, value := range values {
			if value == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
