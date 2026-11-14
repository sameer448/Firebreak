# PB-PHISH-01 Phishing Payload Execution

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
Macro documents spawning shells or script hosts, malicious attachments, links to newly registered domains.

## Response steps
- Isolate the host.
- Run a mailbox-wide Search and Purge on the message ID.
- Submit the attachment to the sandbox.
- Reset the user's credentials and check inbox rules for auto-forwarding.

## SLA
purge completed within 1 hour of confirmation.

## Additional guidance
Notify the user's manager and remind the user how to report phishing.
