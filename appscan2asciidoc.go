// appscan2asciidoc
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)

// Struct to hold convoluted AppScan XML structure - at least the bits I need
type AppScan struct {
	//Summary []Summary `xml:"Summary"`
	Results []Results `xml:"Results"`
}

//type Summary struct {
//	Hosts []Hosts `xml:"Hosts"`
//}

//type Hosts struct {
//	Name string `xml:"name,attr"`
//}

type Results struct {
	RemediationTypes []RemediationTypes `xml:"RemediationTypes"`
	IssueTypes       []IssueTypes       `xml:"IssueTypes"`
	Issues           []Issues           `xml:"Issues"`
}

//
// RemediationTypes and children
//
type RemediationTypes struct {
	RemediationType []RemediationType `xml:"RemediationType"`
}

type RemediationType struct {
	ID                string              `xml:"ID,attr"`
	fixRecommendation []fixRecommendation `xml:"fixRecommendation"`
	Priority          string              `xml:"Priority"`
}

type fixRecommendation struct {
	text    []text `xml:"text"`
	fixType string `xml:"type,attr"`
}

type text struct {
	text string `xml:"text"`
}

//
// IssueTypes and children
//
type IssueTypes struct {
	IssueType []IssueType `xml:"IssueType"`
}

type IssueType struct {
	ID            string     `xml:"ID,attr"`
	RemediationID string     `xml:"RemediationID"`
	advisory      []advisory `xml:"advisory"`
}

type advisory struct {
	name          string          `xml:"name"`
	ttDesc        []ttDesc        `xml:"testTechnicalDescription"`
	securityRisks []securityRisks `xml:"securityRisks"`
	cwe           []cwe           `xml:"cwe"`
}

type ttDesc struct {
	text []text `xml:"text"`
}

// Note text type already defined above

type securityRisks struct {
	securityRisk []securityRisk `xml:"securityRisk"`
}

type securityRisk struct {
	securityRisk string `xml:"securityRisk"`
}

type cwe struct {
	link []link `xml:"link"`
}

type link struct {
	cweUrl string `xml:"target,attr"`
	cweID  string `xml:"id,attr"`
}

//
// Issues and children
//
type Issues struct {
	Issue []Issue `xml:"Issue"`
}

type Issue struct {
	Severity string   `xml:"Severity"`
	Url      string   `xml:'Url'`
	Entity   []Entity `xml:"Entity"`
}

type Entity struct {
	Paramenter string `xml:"Name,attr"`
	ParaType   string `xml:"Type,attr"`
}

//
// Maps for linking data from different XML branches
//
var title = make(map[string]string)

var desc = make(map[string]string)

var impact = make(map[string]string)

var cweMap = make(map[string]string)

var miti = make(map[string]string)

func main() {
	fmt.Println("Hello AppScan!")

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
	var findings AppScan

	err = xml.Unmarshal(bytes, &findings)
	if err != nil {
		fmt.Println("Error parsing file:\n\t", err)
		os.Exit(1)
	}

	// Create title map
	for i := range findings.Results[0].IssueTypes[0].IssueType {
		index := findings.Results[0].IssueTypes[0].IssueType[i].ID
		//txt := findings.Results[0].IssueTypes[0].IssueType[i].advisory[0].name
		txt := "blah"

		//title[index] = findings.Results[0].IssueTypes[0].IssueType[i].advisory[0].name
		//fmt.Printf("interation %d is %s", i, findings.Results[0].IssueTypes[0].IssueType[i].advisory[0].name)
		fmt.Printf("interation %d : %s\n%s\n", i, index, txt)
	}

	//fmt.Printf("\n\nCompile! %+v\n", len(findings.Results[0].IssueTypes[0].IssueType[0].RemediationID))
	fmt.Printf("\n\nCompile! %+v\n", findings.Results[0])

	fmt.Println("\n\n===== next test =====\n\n")

	file2, err := os.Open(file) // For read access.
	if err != nil {
		//log.Fatal(err)
		os.Exit(1)
	}

	decoder := xml.NewDecoder(file2)

	fmt.Printf("\nWorks %v", decoder)

	for {
		// Read in tokens from the XML document stream
		t, _ := decoder.Token()
		if t == nil {
			break
		}

		// Look at the curren token for the one we want
		switch se := t.(type) {
		case xml.StartElement:
			// Look for Advisory to test this
			if se.Name.Local == "advisory" {
				fmt.Printf("advisory element found called %v", se.Name.Local)
			}
		}
	}

}
