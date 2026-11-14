# Known False Positives

Owner: SOC. Recurring benign activity that matches detection rules. The triage agent retrieves these to recognise benign look-alikes; the guardrails still apply.

## Example: software deployment agent
Your deployment tool's signed agent running encoded PowerShell from its install path is expected during patch windows. Anything with the same name from a user-writable path is not.
