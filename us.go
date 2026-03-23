package packs

// Source: US phone — common NANP format
// Source: US SSN — formatted ddd-dd-dddd only (unformatted \d{9} removed per false-positive risk)
// Source: US address — keyword-anchored street pattern

import (
	"net"
	"regexp"
)

func init() {
	Register(
		Entry{
			Name: "us_phone",
			Pack: "US",
			// Requires at least one separator between area code and exchange to avoid
			// matching raw hex digit runs inside PII tokens.
			Re:         regexp.MustCompile(`(\+?1[\-.\s])?\(?([0-9]{3})\)?[\-.\s]([0-9]{3})[\-.\s]?([0-9]{4})`),
			PIIType:    "PHONE",
			Confidence: 0.65,
			Validate:   validateUSPhone,
		},
		Entry{
			Name: "us_ssn",
			Pack: "US",
			// Only formatted SSN (ddd-dd-dddd) to avoid false positives on arbitrary 9-digit numbers.
			Re:         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			PIIType:    "SSN",
			Confidence: 0.85,
		},
		Entry{
			Name:       "us_address",
			Pack:       "US",
			Re:         regexp.MustCompile(`(?i)\d+\s+[A-Za-z]+(?:\s+[A-Za-z]+){0,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.75,
		},
		Entry{
			Name:       "ipv6",
			Pack:       "US",
			Re: regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,7}:` +
				`|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}` +
				`|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}` +
				`|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}` +
				`|:(?::[0-9a-fA-F]{1,4}){1,7}` +
				`|::`,
			),
			PIIType:    "IPADDRESS",
			Confidence: 0.85,
		},
		Entry{
			Name:       "ipv4",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			PIIType:    "IPADDRESS",
			Confidence: 0.70,
			Validate:   validateIPv4,
		},
	)
}

// validateIPv4 checks that each octet is in the range 0-255.
func validateIPv4(s string) bool {
	return net.ParseIP(s) != nil
}

// validateUSPhone rejects area codes starting with 0 or 1 (invalid in NANP).
func validateUSPhone(s string) bool {
	// Extract the area code — the regex captures it in group 2.
	re := regexp.MustCompile(`\(?([0-9]{3})\)?`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return false
	}
	areaCode := m[1]
	return areaCode[0] != '0' && areaCode[0] != '1'
}
