# PB-WEB-01 Web Server Compromise

Owner: Incident Response. Severity guidance and steps below are mandatory for this alert category.

## Applies to
w3wp.exe or other web server processes spawning shells, new web pages outside deployments.

## Response steps
- Remove the server from the load balancer pool.
- Snapshot the VM before remediation.
- Collect IIS logs and the web root.
- Rotate application secrets and service account credentials.

## Additional guidance
Check every web server for similar new files in the web root.
