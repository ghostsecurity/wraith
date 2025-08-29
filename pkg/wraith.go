package wraith

type ScanResult struct {
	Package              string
	Version              string
	FoundVulnerabilities []Vulnerability
}

type Vulnerability struct {
	ID          string
	Description string
}
