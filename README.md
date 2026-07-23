# SwanWatch multi-distribution installer

This bundle installs a Dockerized strongSwan IKEv2 VPN and the SwanWatch web dashboard.

## Supported hosts

- Debian 12
- Debian 13 (Trixie)
- CentOS Stream 9 or newer
- RHEL 9 or newer
- Rocky Linux 9 or newer
- AlmaLinux 9 or newer
- Oracle Linux 9 or newer

The installer detects the host family automatically. Debian 12/13 use `apt` and persistent iptables rules. On Debian 13 the installer explicitly installs the separate `docker-cli` package required by the distribution's Docker packaging. RHEL-compatible systems use Docker's official RPM repository, `dnf`, SELinux-compatible container settings, and `firewalld`.

## What it configures

- Docker Engine and the Docker Compose plugin
- strongSwan with IKEv2, server certificates, and EAP-MSCHAPv2 users
- Automatic `swanctl --load-all` whenever the VPN container starts
- IPv4 forwarding, NAT, UDP 500/4500, and LAN-restricted dashboard access
- SwanWatch user management, monitoring, backups, and service controls
- A dashboard bound to the selected server LAN IPv4 address

## Important warning

The installer generates a new private CA and server certificate. Replacing an existing VPN means existing clients must import the newly generated CA certificate. Back up a working VPN first.

The installer uses the container names `strongswan` and `swanwatch`. Stop or rename existing containers with those names before installation.

## Install

```bash
unzip swanwatch-installer-debian13-centos9.zip
cd swanwatch-installer
sudo ./install.sh
```

The installer prompts for the public hostname, network interface, server address, trusted LAN subnet, VPN subnet, DNS servers, VPN credentials, and dashboard credentials.

Installation details are stored root-only at:

```text
/opt/swanwatch/INSTALL-CREDENTIALS.txt
```

## CentOS/RHEL notes

The installer enables `firewalld` and adds:

- UDP 500 and UDP 4500 in the interface's active zone
- Masquerading for VPN client Internet access
- A source rule permitting the VPN client subnet
- A source-restricted rule permitting the dashboard only from the trusted LAN subnet

Docker containers use `label=disable` because strongSwan needs privileged host networking and SwanWatch intentionally mounts the Docker socket and host monitoring paths. Do not expose the dashboard port through your router.

## Router configuration

Forward to the VPN server:

- UDP 500
- UDP 4500

## Client setup

Import:

```text
/opt/swanwatch/strongswan/swanctl/x509ca/ca-cert.pem
```

Then create an IKEv2 EAP username/password profile using the public hostname supplied during installation.

## Useful commands

```bash
cd /opt/swanwatch
docker compose ps
docker exec strongswan swanctl --list-conns
docker exec strongswan swanctl --list-sas
docker logs strongswan --tail 100
docker logs swanwatch --tail 100
```

## Important IPsec router note

The installer builds a dedicated strongSwan 6.0.6 image with the `eap-mschapv2` and `md4` plugins enabled. These plugins are required for the configured IKEv2 EAP username/password authentication.

If the upstream router is itself running an IPsec/IKEv2 VPN server (including many DrayTek routers), it may consume UDP 500 and UDP 4500 before port forwarding is applied. Disable the router's IPsec service, use a different public IP/WAN, or use a different VPN protocol on one endpoint. Forward UDP 500 and 4500 to the SwanWatch server.

After installation, verify the required plugin with:

```bash
docker exec strongswan swanctl --stats | grep eap-mschapv2
```
# SwanWatch
# SwanWatch
# SwanWatch
