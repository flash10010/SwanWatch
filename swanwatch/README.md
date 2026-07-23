# MyPCHelp strongSwan Dashboard v4

Version 4 adds dashboard-managed EAP users to the v3 server console.

## New user-management features

- Add EAP username/password accounts
- Generate a strong random password and show it once
- Reset a user's password
- Delete a managed user
- Reload credentials with `swanctl --load-creds --clear --noprompt`
- Record user changes in the dashboard activity log
- Keep the main `swanctl.conf`, certificates and private key read-only

The dashboard only manages accounts stored in:

```text
strongswan-dashboard/managed-users/dashboard-users.conf
```

Existing accounts in your main `swanctl.conf`, including `vpnuser`, remain untouched and are not listed in the dashboard.

## Required one-time strongSwan integration

The managed file must be visible inside the strongSwan container and included by `swanctl.conf`.

### 1. Add the managed directory to the strongSwan container

Edit the Docker Compose file that defines your existing `strongswan` service. Under that service's `volumes:` section, add:

```yaml
- ./strongswan-dashboard/managed-users:/etc/swanctl/dashboard-users:ro
```

This path assumes your strongSwan Compose file is in `~/strongswan` and the dashboard is in `~/strongswan/strongswan-dashboard`.

### 2. Include the managed users file

At the top level of the `swanctl.conf` used by the strongSwan container, add:

```conf
include dashboard-users/*.conf
```

Place it outside the `connections`, `pools`, and `secrets` blocks. For example:

```conf
include dashboard-users/*.conf

connections {
    # existing VPN connection
}

pools {
    # existing address pool
}

secrets {
    # existing server key and vpnuser account
}
```

The included dashboard file contains its own `secrets { ... }` section.

### 3. Recreate strongSwan once

From `~/strongswan`:

```bash
docker compose up -d --force-recreate strongswan
```

Verify the include is readable:

```bash
docker exec strongswan sh -lc 'cat /etc/swanctl/dashboard-users/dashboard-users.conf'
```

Then verify credentials reload:

```bash
docker exec strongswan swanctl --load-creds --clear --noprompt
```

## Upgrade the dashboard

Preserve your current dashboard credentials from the old `docker-compose.yml`, then replace the dashboard folder with this version.

```bash
cd ~/strongswan
docker compose -f strongswan-dashboard/docker-compose.yml down
mv strongswan-dashboard strongswan-dashboard-v3-backup
unzip strongswan-dashboard-v4.zip
mv strongswan-dashboard-v4 strongswan-dashboard
```

Edit the new dashboard Compose file and restore your existing values:

```bash
nano ~/strongswan/strongswan-dashboard/docker-compose.yml
```

At minimum, change:

```yaml
DASHBOARD_USER: admin
DASHBOARD_PASSWORD: use-a-strong-password
FLASK_SECRET_KEY: use-a-long-random-value
```

Generate a Flask secret with:

```bash
openssl rand -hex 32
```

Build and start:

```bash
cd ~/strongswan/strongswan-dashboard
docker compose build --no-cache
docker compose up -d
```

Verify:

```bash
docker logs vpn-dashboard --tail 100
curl http://192.168.0.70:8085/health
```

Open:

```text
http://192.168.0.70:8085
```

## Test adding a user

Use the **Add user** button, enter a name such as `firestick`, and save the displayed password.

Confirm it was loaded:

```bash
docker exec strongswan swanctl --list-creds
```

The user can then connect with:

```text
Server: mypchelp.duckdns.org
VPN type: IKEv2 EAP username/password
Username: firestick
Password: the generated password
CA certificate: your existing MyPCHelp VPN Root CA
```

## Security notes

- Keep TCP 8085 LAN-only. Do not forward it on the router.
- The dashboard has access to the Docker socket, so use a strong password.
- Generated passwords are returned only when created or reset. The dashboard does not display stored passwords later.
- Deleting a user blocks future authentication. An already-established tunnel may remain active until disconnected or expired.
- Back up the strongSwan project before the first upgrade.
