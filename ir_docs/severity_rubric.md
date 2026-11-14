# IR-SEV-01 Incident Severity Rubric

Owner: Incident Response. The IR agent extracts facts; this rubric assigns the severity. Severity is never chosen by the model directly.

## Scoring
Severity score = asset criticality points + impact points + scope points.
Asset criticality: critical (domain controllers, Tier-0 identity systems) = 3; high (database, file, backup, admin jump, internet-facing web and security tooling servers; Finance workstations) = 2; medium (other workstations and application servers) = 1; low (lab and test hosts) = 0.
Impact: none = 0; attempted (blocked or failed) = 1; executed (attacker code or commands ran) = 2; exposed (credentials or data were exposed or staged) = 3; destructive (encryption, deletion, or recovery inhibited) = 4.
Scope: single host = 0; multiple hosts = 1; domain-wide = 2.

## Severity levels
SEV1: score 7 or more, OR any Tier-0 asset or account is involved, OR destructive impact (ransomware). Page IR on-call immediately; CISO informed within 1 hour.
SEV2: score 5 to 6. Page IR on-call; IR lead acknowledges within 30 minutes.
SEV3: score 3 to 4. War-room channel and case; handled in business hours, no page.
SEV4: score 0 to 2. Case only; no war-room, no page.

## Overrides
Data exfiltration confirmed or suspected raises severity by one level (minimum SEV2) and requires the privacy officer.
A disabled or offboarded account showing any activity is at least SEV2.
Credential theft techniques (T1003, T1558, T1555, T1552) and exfiltration techniques (T1567, T1048, T1041, T1537, T1020) confirmed by triage count as exposed impact at minimum.
A True Positive with no sign that the activity was blocked counts as executed impact at minimum.
