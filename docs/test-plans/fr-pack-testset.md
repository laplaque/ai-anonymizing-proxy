# FR Pack Test Set

Use these messages to test FR pack PII detection through the proxy. Each contains synthetic but **checksum-valid** PII.

> **Changelog (v2):** All NIR values now have correct mod-97 keys. All SIRET/SIREN
> values are Luhn-valid. Negative test extension number uses a non-Luhn, non-9-digit
> value to avoid SIREN and SSN cross-matches. SIRET phone-like edge case uses standard
> 3+3+3+5 grouping. DE test values unchanged (space-formatting is a pre-existing DE
> pack gap — DE Steuer-ID, SVNR will fail until DE pack gets space-tolerant regexes).

> **Test config:** `EnabledPacks: ["GLOBAL", "US", "DE", "FR", "SECRETS"]`, `UseAI: false`, `PackDecayRate: 0.0`

---

## NIR (Numéro d'Inscription au Répertoire) — Social Security

### Should detect

"Bonjour, je vous envoie mon numéro de sécurité sociale pour le dossier: 1 85 12 75 108 042 79. Merci de le traiter en urgence."

"Le patient masculin né en mars 1990 en Corse-du-Sud porte le NIR 1 90 03 2A 014 012 75 et doit être enregistré dans le système."

"Pour la déclaration, mon numéro est 2 78 06 99 341 002 50. Pouvez-vous vérifier?"

### NIR with Corsica department codes (2A/2B)

"NIR du résident corse: 1 90 03 2A 014 012 75"
"Autre résident: 2 87 11 2B 033 001 59"

---

## SIRET (14 digits — SIREN + NIC)

### Should detect

"Veuillez envoyer la facture à notre entreprise, SIRET 362 521 874 00036, pour le traitement comptable."

"Le prestataire a le numéro SIRET 443 061 841 00013, basé à Lyon."

### SIRET that looks like a phone number

"Contact: 362 521 874 00036 — this should be detected as SIRET, not phone."

---

## SIREN (9 digits)

### Should detect

"L'entreprise est immatriculée sous le SIREN 362 521 874 au registre du commerce."

"Vérifiez le SIREN 443 061 841 dans la base SIRENE avant de procéder."

---

## Mixed content — FR and DE in one message

"Unsere französische Niederlassung (SIRET 362 521 874 00036) hat einen neuen Mitarbeiter eingestellt. Seine Steuer-ID ist 65 929 970 489 und seine französische Sozialversicherungsnummer lautet 1 85 12 75 108 042 79. Bitte alles im HR-System erfassen."

---

## Multiple PII types in one sentence

"Le contrat réf. SIREN 362 521 874 concerne M. Dupont, NIR 1 85 12 75 108 042 79, domicilié au 15 rue de la Paix, 75002 Paris."

---

## Negative tests — should NOT trigger

"The reference number is 12345678901 and the order total is 362.52."

"Please call us at extension 44306183 for more information."

"Meeting scheduled for 1 85 12 at conference room 042 on the 36th floor."

---

## Checksum verification reference

### NIR (mod 97): key = 97 - (base13 % 97)

| Description | Base (13 digits) | Key | Full NIR |
|---|---|---|---|
| Male, Dec 1985, dept 75 | 1851275108042 | 79 | 1 85 12 75 108 042 79 |
| Male, Mar 1990, Corsica 2A (sub 19) | 1900319014012 | 75 | 1 90 03 2A 014 012 75 |
| Female, Jun 1978, dept 99 | 2780699341002 | 50 | 2 78 06 99 341 002 50 |
| Female, Nov 1987, Corsica 2B (sub 18) | 2871118033001 | 59 | 2 87 11 2B 033 001 59 |

### SIRET/SIREN (Luhn algorithm)

| Type | Value | Luhn valid |
|---|---|---|
| SIREN | 362 521 874 | Yes |
| SIREN | 443 061 841 | Yes |
| SIRET | 362 521 874 00036 | Yes |
| SIRET | 443 061 841 00013 | Yes |
| Negative (extension) | 44306183 (8 digits) | No (and not 9 digits, avoids SSN) |
