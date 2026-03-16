import subprocess

firewall_enabled = False
blocked_ips = set()


def enable_auto_block():
    global firewall_enabled
    firewall_enabled = True
    print("[FIREWALL] Auto blocking enabled")


def disable_auto_block():
    global firewall_enabled
    global blocked_ips

    firewall_enabled = False
    blocked_ips.clear()

    print("[FIREWALL] Auto blocking disabled")


def is_enabled():
    return firewall_enabled


def block_ip(ip, reason="attack"):

    global blocked_ips

    if not firewall_enabled:
        return

    if not ip:
        return

    try:
        # Check if rule already exists in FORWARD chain
        check = subprocess.run(
            ["sudo", "iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if check.returncode == 0:
            # Rule already exists
            return

        print(f"[FIREWALL] Blocking {ip} ({reason})")

        # Block forwarded traffic (gateway traffic)
        subprocess.run(
            ["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Block traffic to the AEPS host itself (ping, local services)
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        blocked_ips.add(ip)

        print(f"[FIREWALL] {ip} successfully blocked")

    except Exception as e:
        print("[FIREWALL ERROR]", e)


def get_blocked_ips():
    return list(blocked_ips)
