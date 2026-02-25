package sbom

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/qualys/eventgen/pkg/qualys"
)

type CBOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     CBOMMetadata `json:"metadata"`
	Components   []Component  `json:"components"`
}

type CBOMMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []Tool          `json:"tools"`
	Component *ImageComponent `json:"component,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ImageComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	PURL       string              `json:"purl,omitempty"`
	Licenses   []License           `json:"licenses,omitempty"`
	Hashes     []Hash              `json:"hashes,omitempty"`
	Properties []Property          `json:"properties,omitempty"`
	Vulns      []VulnRef           `json:"vulnerabilities,omitempty"`
}

type License struct {
	ID string `json:"id,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type VulnRef struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	CVSS     float64 `json:"cvss,omitempty"`
}

type Generator struct {
	client *qualys.Client
}

func NewGenerator(client *qualys.Client) *Generator {
	return &Generator{client: client}
}

func (g *Generator) GenerateFromImage(imageID string, includeVulns bool) (*CBOM, error) {
	cbom := &CBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", imageID),
		Version:      1,
		Metadata: CBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "Qualys",
				Name:    "qcr",
				Version: "1.0.3",
			}},
		},
		Components: []Component{},
	}

	images, err := g.client.GetImages(100, false)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch images: %w", err)
	}

	var targetImage *qualys.ContainerImage
	for i := range images {
		if images[i].ImageID == imageID {
			targetImage = &images[i]
			break
		}
	}

	if targetImage == nil {
		return nil, fmt.Errorf("image not found: %s", imageID)
	}

	cbom.Metadata.Component = &ImageComponent{
		Type:    "container",
		Name:    targetImage.Repo,
		Version: targetImage.Tag,
	}

	return cbom, nil
}

func (g *Generator) GenerateFromRunningContainers(limit int) ([]*CBOM, error) {
	containers, err := g.client.GetRunningContainers(limit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch containers: %w", err)
	}

	imageIDs := make(map[string]bool)
	for _, c := range containers {
		imageIDs[c.ImageID] = true
	}

	var cboms []*CBOM
	for imageID := range imageIDs {
		cbom, err := g.GenerateFromImage(imageID, true)
		if err != nil {
			continue
		}
		cboms = append(cboms, cbom)
	}

	return cboms, nil
}

func (c *CBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func (c *CBOM) ToSPDX() ([]byte, error) {
	spdx := map[string]interface{}{
		"spdxVersion":    "SPDX-2.3",
		"dataLicense":    "CC0-1.0",
		"SPDXID":         "SPDXRef-DOCUMENT",
		"name":           c.Metadata.Component.Name,
		"documentNamespace": fmt.Sprintf("https://qualys.com/cbom/%s", c.SerialNumber),
		"creationInfo": map[string]interface{}{
			"created": c.Metadata.Timestamp,
			"creators": []string{
				"Tool: qcr-1.0.3",
				"Organization: Qualys",
			},
		},
		"packages": convertToSPDXPackages(c.Components),
	}

	return json.MarshalIndent(spdx, "", "  ")
}

func convertToSPDXPackages(components []Component) []map[string]interface{} {
	packages := make([]map[string]interface{}, 0, len(components))
	for i, comp := range components {
		pkg := map[string]interface{}{
			"SPDXID":           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			"name":             comp.Name,
			"versionInfo":      comp.Version,
			"downloadLocation": "NOASSERTION",
		}
		if comp.PURL != "" {
			pkg["externalRefs"] = []map[string]string{{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType":     "purl",
				"referenceLocator":  comp.PURL,
			}}
		}
		packages = append(packages, pkg)
	}
	return packages
}

func SeverityFromCVSS(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "CRITICAL"
	case cvss >= 7.0:
		return "HIGH"
	case cvss >= 4.0:
		return "MEDIUM"
	case cvss > 0:
		return "LOW"
	default:
		return "NONE"
	}
}
