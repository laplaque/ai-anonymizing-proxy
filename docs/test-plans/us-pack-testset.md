# US Pack Test Set

Use these messages to test US pack PII detection through the proxy. Covers all 6 US patterns: SSN, Phone, Address, IPv4, IPv6, ZIP.

> **Test config:** `EnabledPacks: ["GLOBAL", "US", "DE", "FR", "SECRETS"]`, `UseAI: false`, `PackDecayRate: 0.0`

---

## 1. SSN (Social Security Number -- 9 digits, area code validation)

### 1.1 Should detect

"My SSN is 123-45-6789."
> Hyphenated format. Area 123 valid, group 45 valid, serial 6789 valid.

"SSN 001-01-0001 is the lowest valid."
> Area 001 is the lowest valid area code.

"SSN 899-99-9999 is highest before invalid range."
> Area 899 is the last valid area code before the 900+ exclusion.

### 1.2 Should NOT detect

"SSN: 123456789 on file."
> Contiguous 9 digits, no hyphens. SSN regex requires hyphens (fix #69: prevents cross-pattern interference with SIREN).

"SSN 000-12-3456 rejected."
> Area 000 has never been issued.

"SSN 666-12-3456 rejected."
> Area 666 has never been issued.

"SSN 900-12-3456 rejected."
> Area >= 900 has never been issued.

"SSN 999-99-9999 rejected."
> Area 999 in the excluded range.

"SSN 123-00-6789 rejected."
> Group 00 has never been issued.

"SSN 123-45-0000 rejected."
> Serial 0000 has never been issued.

---

## 2. Phone (US format -- NANPA, requires non-dot separator)

### 2.1 Should detect

"Call 555-867-5309 for info."
> Hyphenated format.

"Phone: (212) 555-0100."
> Parenthesized area code.

"Reach us at +1-800-555-1234."
> With +1 country code.

"Number: 555 867 5309 available."
> Space-separated format.

### 2.2 Should NOT detect (validator rejects)

"Version 555.867.5309 released."
> Dot-only separators rejected by validator (looks like version string).

"Dial 5558675309 now."
> Pure digits with no separator -- too ambiguous, validator rejects.

---

## 3. Address (US street format -- requires street type suffix)

### 3.1 Should detect

"Lives at 123 Main Street in town."

"Office at 456 Elm Ave downtown."

"Located at 789 Oak Boulevard."

"Turn onto 100 Pine Road ahead."

"Delivery to 42 Maple Lane."

"Meet at 555 Cedar Drive."

"Parked near 10 Birch Court."

"Ship to 321 Oak St please."
> Abbreviated suffix "St".

### 3.2 Known false positive

"Code 12345 ist falsch."
> KNOWN BUG (#68): German "ist" matches as "i" + "St" suffix. US address regex `(?i)\d+\s+[A-Za-z\s]+St\b` triggers.

---

## 4. IPv4 (dotted quad notation)

### 4.1 Should detect

"Server at 192.168.1.1 running."
> Private network (RFC 1918).

"Bind to 127.0.0.1 for local."
> Loopback address.

"DNS: 8.8.8.8 configured."
> Google public DNS.

"Broadcast 255.255.255.255 sent."
> Broadcast address.

---

## 5. IPv6 (RFC 5952 all forms)

### 5.1 Should detect

"Host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334."
> Full uncompressed form.

"Loopback: ::1 configured."
> Compressed loopback.

"Interface fe80:: detected."
> Link-local prefix.

"Address 2001:db8::1 in use."
> Compressed with zero omission.

---

## 6. ZIP Code (5 digits, optional +4)

### 6.1 Should detect

"Ship to 90210 please."
> 5-digit ZIP. Maps to ADDRESS type. Confidence 0.40 (very low).

"ZIP: 90210-1234 on label."
> ZIP+4 format.

---

## 7. Negatives -- should NOT trigger

"The quick brown fox jumps."
> Plain text, no PII.

"Running v2.345.678.9012 build."
> Version string. Phone validator rejects dot-only separators.

"Order 42 confirmed."
> Too few digits for any US pattern.

"Ref number 12345678 noted."
> 8 digits. Not 9 (SSN), not 5 (ZIP), no phone separators.

---

## 8. Edge cases

### 8.1 SSN + Phone in one message

"SSN 123-45-6789, phone 555-867-5309."
> Both detected: PII_SSN + PII_PHONE.

### 8.2 Address + ZIP in one sentence

"Lives at 123 Main Street, 90210."
> Both detected as PII_ADDRESS (address pattern + ZIP pattern).

### 8.3 IPv4 + IPv6 together

"Hosts: 192.168.1.1 and 2001:db8::1."
> Both detected as PII_IPADDRESS.

### 8.4 All US types in one message

"SSN 123-45-6789, phone (212) 555-0100, 123 Main Street, 90210, server 192.168.1.1."
> Should detect: SSN + PHONE + ADDRESS + ADDRESS(ZIP) + IPADDRESS.

---

## 9. Test results (verified against commit f2fb6ea)

43 passed, 0 warned, 0 failed out of 43
