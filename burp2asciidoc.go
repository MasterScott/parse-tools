// burp2asciidoc
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

type Issues struct {
	Issue []Issue `xml:"issue"`
}

type Issue struct {
	SerialNum string `xml:"serialNumber"`
	BurpType  string `xml:"type"`
	Name      string `xml:"name"`
	Host      []Host `xml:"host"`
	Path      string `xml:"path"`
	Location  string `xml:"location"`
	Severity  string `xml:"severity"`
	Confid    string `xml:"confidence"`
	Details   string `xml:"issueBackground"`
	Remed     string `xml:"remediationBackground"`
}

type Host struct {
	IPAddr   string `xml:"ip,attr"`
	Hostname string `xml:",chardata"`
}

var burp2cve = map[string]string{
	// Frameable response (potential Clickjacking)
	"5245344": "http://cwe.mitre.org/data/definitions/693.html[CWE-693: Protection Mechanism Failure]",
	// Cross-site scripting (reflected)
	"2097920": "http://cwe.mitre.org/data/definitions/80.html[CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)]",
	// Email addresses disclosed
	"6291968": "http://cwe.mitre.org/data/definitions/200.html[CWE-200: Information Exposure]",
	// SQL injection
	"1049088": "http://cwe.mitre.org/data/definitions/89.html[CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')]",
	// Content type incorrectly stated
	"8389632": "http://cwe.mitre.org/data/definitions/16.html[CWE-16: Configuration]",
	// Cookie without HttpOnly flag set
	"5244416": "http://cwe.mitre.org/data/definitions/693.html[CWE-693: Protection Mechanism Failure]",
	// Cacheable HTTPS response
	"7340288": "http://cwe.mitre.org/data/definitions/693.html[CWE-693: Protection Mechanism Failure]",
	// Cookie scoped to parent domain
	"5243648": "http://cwe.mitre.org/data/definitions/539.html[CWE-539: Information Exposure Through Persistent Cookies]",
	// SSL cookie without secure flag set
	"5243392": "http://cwe.mitre.org/data/definitions/319.html[CWE-319: Cleartext Transmission of Sensitive Information]",
	// Robots.txt file
	"6292992": "http://cwe.mitre.org/data/definitions/16.html[CWE-16: Configuration]",
	// File upload functionality
	"5245312": "http://cwe.mitre.org/data/definitions/434.html[CWE-434: Unrestricted Upload of File with Dangerous Type]",
	// Cross-domain Referer leakage
	"5243904": "http://cwe.mitre.org/data/definitions/693.html[CWE-693: Protection Mechanism Failure]",
	// Password field with autocomplete enabled
	"5244928": "http://cwe.mitre.org/data/definitions/522.html[CWE-522: Insufficiently Protected Credentials]",
	// Private IP addresses disclosed
	"6292224": "http://cwe.mitre.org/data/definitions/200.html[CWE-200: Information Exposure]",
	// Cross-domain POST
	"4195584": "http://cwe.mitre.org/data/definitions/693.html[CWE-693: Protection Mechanism Failure]",
	// TRACE method is enabled
	"5245440": "http://cwe.mitre.org/data/definitions/16.html[CWE-16: Configuration]",
	// SSL certificate
	"16777472": "http://cwe.mitre.org/data/definitions/16.html[CWE-16: Configuration]"}

func main() {
	// Make sure we got a file argument
	if len(os.Args) != 2 {
		fmt.Println("Usage: ", os.Args[0], "file")
		os.Exit(1)
	}
	// And we can open it successfully
	file := os.Args[1]
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Error reading file:\n\t", err)
		return
	}

	// Parse XML into the Issues struct
	var findings Issues

	err = xml.Unmarshal(bytes, &findings)
	if err != nil {
		fmt.Println("Error parsing file:\n\t", err)
		os.Exit(1)
	}

	// Generate an asciidoc report of findings
	report := ""
	findingCount := 0

	for i := range findings.Issue {
		if reportable(findings.Issue[i].BurpType) {
			findingCount++
			// Build a finding block
			report += genAsciidoc(findingCount, "start", "")
			report += genAsciidoc(i, "title", findings.Issue[i].Name)
			report += genAsciidoc(i, "severity", findings.Issue[i].Severity)
			report += genAsciidoc(i, "sys-start", "")
			// Iterate through the systems for this finding
			for j := range findings.Issue[i].Host {
				report += genAsciidoc(i, "host", findings.Issue[i].Host[j].Hostname)
				report += genAsciidoc(i, "ip", findings.Issue[i].Host[j].IPAddr)
			}
			report += genAsciidoc(i, "path", findings.Issue[i].Path)
			report += genAsciidoc(i, "loc", findings.Issue[i].Location)
			report += genAsciidoc(i, "desc", findings.Issue[i].Details)
			report += genAsciidoc(i, "miti", findings.Issue[i].Remed)
			report += genAsciidoc(i, "impact", "")
			report += genAsciidoc(i, "refer", findings.Issue[i].BurpType)
		}
	}
	fmt.Printf("%s\n", report)

}

func genAsciidoc(issNum int, place string, value string) string {
	reportChunk := ""

	// Create a bit of the report based on the place sent in
	// and use issNum to count the number of findings
	switch place {

	case "start":
		reportChunk = "=== Finding " + formatFindingNum(issNum) + ": "
	case "title":
		reportChunk = value + " ===\n\n"
	case "severity":
		reportChunk = "*Severity:* " + convertSeverity(value) + "\n\n"
	case "sys-start":
		reportChunk = "*Systems:* +\n"
	case "host":
		reportChunk = value + " / "
	case "ip":
		reportChunk = value + " +\n"
	case "path":
		reportChunk = "  Path: " + value + " +\n"
	case "loc":
		reportChunk = "  Location: " + value + "\n\n"
	case "desc":
		reportChunk = "*Details and Mitigation:*\n\n" + value + "\n\n"
	case "miti":
		reportChunk = "Mitigation: \n\n" + value + "\n\n"
	case "impact":
		reportChunk = "*Impact:*\n\n*FILL THIS BIT OUT PLEASE*\n\n"
	case "refer":
		// Check for value as a key in the burp2cve map
		cwe, ok := burp2cve[value]
		if ok {
			reportChunk = "*References:*\n\n" + cwe + "\n\n"
		} else {
			reportChunk = "*References:*\n\n" + "BUG: Missing Burp type " + value + " in burp2cve map\n\n"
		}
	default:
		reportChunk = "BUG: switch case miss in genAsciidoc"
	}
	return reportChunk
}

func formatFindingNum(count int) string {
	// Convert to string and get length
	findingNum := strconv.Itoa((count))
	size := len(findingNum)

	// Pad finding number as needed
	switch size {
	case 1:
		return "00" + findingNum
	case 2:
		return "0" + findingNum
	default:
		return findingNum
	}
}

func convertSeverity(burpSev string) string {
	// Convert Burp's severity rating to Rack's severity rating
	switch burpSev {
	case "Information":
		return "S4"
	case "Low":
		return "S3"
	case "Medium":
		return "S2"
	case "High":
		return "S1"
	default:
		return "BUG: New Burp Severity Type - update the code for " + burpSev
	}
}

func reportable(burpType string) bool {
	// Use the map below to store issues not worth reporting
	burpExclude := map[string]string{
		"8389632":  "Content type incorrectly stated",
		"6291968":  "Email addresses disclosed",
		"7340288":  "Cacheable HTTPS response",
		"6292224":  "Private IP addresses disclosed",
		"4195584":  "Cross-domain POST",
		"16777472": "SSL certificate",
		"5243904":  "Cross-domain Referer leakage",
		"6292992":  "Robots.txt file",
	}

	for exclude, _ := range burpExclude {
		if exclude == burpType {
			return false
		}
	}
	return true
}
