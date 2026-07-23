# Security policy

SwanWatch controls strongSwan through the Docker socket. Treat it as a privileged administration service.

- Bind it to a private LAN or management VLAN only.
- Do not forward its HTTP port from the router.
- Prefer a reverse proxy with HTTPS if accessed beyond a trusted LAN.
- Set a unique dashboard password, random Flask secret, and optional TOTP.
- Keep `MANAGED_CONTAINERS` restricted to containers that genuinely need web controls.
- Back up strongSwan configuration before upgrades.

Please report suspected vulnerabilities privately to the project maintainer rather than opening a public issue containing exploit details.
