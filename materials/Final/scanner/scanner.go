package scanner

type Checker interface {
	check(host string, port uint64) *Result
}

type Result struct {
	Vulnerable bool
	Details    string
}
