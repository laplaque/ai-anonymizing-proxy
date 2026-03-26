package packs

import "regexp"

func init() {
	Register(
		// US Social Security Number (SSN): XXX-XX-XXXX or 9 consecutive digits.
		// Source: https://www.ssa.gov/employer/stateweb.htm
		// Pattern reference: Presidio SSN detector.
		// False-positive mitigation: structured hyphenated format is moderately specific.
		Entry{
			Name:       "ssn",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:\d{3}-?\d{2}-?\d{4}|\d{9})\b`),
			PIIType:    "SSN",
			Confidence: 0.85,
		},
		// US phone number: optional +1 country code, area code, 7 digits.
		// Source: NANPA (North American Numbering Plan).
		// Pattern reference: mnestorov/regex-patterns common patterns.
		// False-positive mitigation: broad pattern — low confidence triggers AI fallback.
		Entry{
			Name:       "phone_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`(\+?1?[\-.\s]?)?\(?([0-9]{3})\)?[\-.\s]?([0-9]{3})[\-.\s]?([0-9]{4})`),
			PIIType:    "PHONE",
			Confidence: 0.65,
		},
		// US street address: number + street name + street type suffix.
		// Source: USPS Publication 28 address format guidelines.
		// False-positive mitigation: requires street-type keyword suffix.
		Entry{
			Name:       "address_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`(?i)\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.75,
		},
		// IPv6 address: all RFC 5952 compressed and uncompressed forms.
		// Source: RFC 5952 (IPv6 text representation).
		// False-positive mitigation: colon-hex syntax is structurally unambiguous.
		Entry{
			Name:       "ipv6",
			Pack:       "US",
			Re: regexp.MustCompile(
				`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}` +
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
		// IPv4 address: dotted quad notation.
		// Source: RFC 791 (Internet Protocol).
		// False-positive mitigation: matches version numbers — moderate confidence.
		Entry{
			Name:       "ipv4",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			PIIType:    "IPADDRESS",
			Confidence: 0.70,
		},
		// US ZIP code: 5 digits, optional +4 extension.
		// Source: USPS ZIP code format.
		// False-positive mitigation: very broad — low confidence.
		Entry{
			Name:       "zip_us",
			Pack:       "US",
			Re:         regexp.MustCompile(`\b\d{5}(?:-\d{4})?\b`),
			PIIType:    "ADDRESS",
			Confidence: 0.40,
		},
	)
}
