package packs

import "regexp"

// Source: common US PII format patterns
// Source: IETF RFC 5952 — https://datatracker.ietf.org/doc/html/rfc5952

func init() {
	Register(
		Entry{
			Name:       "us_ssn",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:\d{3}-?\d{2}-?\d{4}|\d{9})\b`),
			PIIType:    "SSN",
			Confidence: 0.85,
		},
		Entry{
			Name:       "us_address",
			Pack:       "US",
			Re:         regexp.MustCompile(`(?i)\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.75,
		},
		Entry{
			Name: "us_ipv6",
			Pack: "US",
			Re: regexp.MustCompile(
				`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` +
					`|(?:[0-9a-fA-F]{1,4}:){1,7}:` +
					`|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}` +
					`|(?:[0-9a-fA-F]{1,4}:){1,5}(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4})` +
					`|(?:[0-9a-fA-F]{1,4}:){1,4}(?:[0-9a-fA-F]{1,4}:){1,2}[0-9a-fA-F]{1,4}` +
					`|(?:[0-9a-fA-F]{1,4}:){1,3}(?:[0-9a-fA-F]{1,4}:){1,3}[0-9a-fA-F]{1,4}` +
					`|(?:[0-9a-fA-F]{1,4}:){1,2}(?:[0-9a-fA-F]{1,4}:){1,4}[0-9a-fA-F]{1,4}` +
					`|[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:){1,5}[0-9a-fA-F]{1,4}` +
					`|:(?::[0-9a-fA-F]{1,4}){1,7}` +
					`|::`,
			),
			PIIType:    "IP",
			Confidence: 0.85,
		},
		Entry{
			Name:       "us_ipv4",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			PIIType:    "IP",
			Confidence: 0.70,
		},
		Entry{
			Name:       "us_phone",
			Pack:       "US",
			Re:         regexp.MustCompile(`(\+?1?[\-.\s]?)?\(?([0-9]{3})\)?[\-.\s]?([0-9]{3})[\-.\s]?([0-9]{4})`),
			PIIType:    "PHONE",
			Confidence: 0.65,
		},
		Entry{
			Name:       "us_zip",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.40,
		},
	)
}
