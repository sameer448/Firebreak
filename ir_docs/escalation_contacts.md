# IR-CONTACT-01 Escalation Contacts and Approval Policy

Owner: Incident Response. Who is engaged for an incident, and which engagements need a human to approve them first.

## Automatic actions (no approval needed)
Open an incident case for every confirmed incident. Create a war-room channel named #inc-<incident id> for SEV1 to SEV3. Post the incident summary to the war-room channel. These are internal and reversible.

## Gated actions (human approval required)
Paging a human responder, and contacting anyone outside the security team, always require approval by the SOC shift lead. The agent proposes; a human approves or denies.

## On-call
IR on-call primary: Alice Morgan (pager rotation ir-primary). Paged for SEV1 and SEV2.

## Stakeholders
CISO (Rahul Desai): SEV1 incidents.
Legal and Privacy Officer (Maria Lopez): any suspected or confirmed data exfiltration; breach-notification decision within 72 hours.
Cyber-insurance carrier: ransomware or destructive incidents, within 1 hour.
External IR retainer partner: SEV1 incidents where a domain controller is involved.
Identity team lead (Kevin Miller): any incident involving credential theft or a privileged account.
