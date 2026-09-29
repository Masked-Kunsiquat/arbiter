package helperpanic

func mustFixture() map[string]string {
	var m map[string]string
	m["k"] = "v" // panics in a helper
	return m
}
