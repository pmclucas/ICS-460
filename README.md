# ICS-460: Network Segmentation Demo

**Description:** Demonstration of how segmentation (through VLANs) and micro-segmentation (by setting firewall policy) can be used to control traffic between departments in an enterprise network.

## Table of Contents

- [Included Files](#included-files)
- [Adding VLAN Interfaces to the Router](#adding-vlan-interfaces-to-the-router)
- [Setting Up Additional Endpoints](#setting-up-additional-endpoints)
- [nftables Policies](#nftables-policies)
  - [nftables-open](#nftables-open)
  - [nftables-hardened](#nftables-hardened)
- [Demonstrating a Denial-of-Service Attack](#demonstrating-a-denial-of-service-attack)

## Included Files

| Directory     | Files |
|---------------|-------|
| `client/`     | `interfaces.conf` |
| `router/`     | `interfaces.conf`, `nftables.conf`, `nftables-open.conf`, `nftables-hardened.conf`, `99-router.conf`, `sysctl.conf` |
| `AttackScript/` | `attack.py` |
| `UtilScripts/`  | `analyze.py`, `netmonitor.py` |

## Adding VLAN Interfaces to the Router

The configuration file is located on the router at `/etc/network/interfaces`.

Additional VLAN interfaces can be added using the template in `interfaces.conf`. For example, to add a new interface for VLAN 3:

```
auto enp0s3.3
    iface enp0s3.3 inet static
    address 10.10.3.1
    netmask 255.255.255.0
    vlan-raw-device enp0s3
```

## Setting Up Additional Endpoints

Additional endpoints can be added by creating new VMs and assigning them to the appropriate VLAN. Set the VM's IP address to an unused address within the VLAN's subnet. Use `client/interfaces.conf` as a template — additional instructions are included within that file.

## nftables Policies

### nftables-open

Allows all traffic between VLANs. Demonstrates the network without firewall restrictions. Apply by running `sudo nft -f /etc/nftables-open.conf` on the router, then restarting the nftables service.

### nftables-hardened

Restricts traffic between VLANs to demonstrate micro-segmentation. Apply by running `sudo nft -f /etc/nftables-hardened.conf` on the router, then restarting the nftables service.

Permitted traffic:
```
Any traffic that's part of an established connection
IT → Employee (all traffic)
Employee → IT (web server access only)
```

## Demonstrating a Denial-of-Service Attack

`attack.py` simulates a denial-of-service attack from a designated attacker VM against a target on the network. It requires [Scapy](https://scapy.net/) to be installed.

**Install dependency:**
```bash
pip install scapy
```

**Run the script:**
```bash
sudo python3 attack.py <target_ip>
```

Replace `<target_ip>` with the IP address of the target VM (e.g., `10.10.1.5`).

The script performs two sequential floods against the target:
- **SYN flood** — sends 50,000 TCP SYN packets to port 80
- **ICMP flood** — sends 50,000 ICMP echo request packets

Use with `nftables-open` to observe unblocked attack traffic, then switch to `nftables-hardened` to see how the firewall policy limits it. Monitor results with Wireshark or `netmonitor.py`.







