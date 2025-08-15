use std::process::Command;
use std::io;

fn run_command(cmd: &str) -> io::Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()?;

    if !status.success() {
        eprintln!("Command failed: {}", cmd);
    }

    Ok(())
}

pub fn setup_tun_interface(
    iface: &str,
    server_ipv4: &str,
    server_ipv6: &str,
    net_if: &str, // e.g., "eth0"
) -> io::Result<()> {
    let commands = vec![
        // Create the TUN interface (optional, may require privileges)
        // format!("ip tuntap add dev {} mode tun", iface),

        // Assign IPv4 and IPv6 to TUN interface
        // format!("ip addr add {} dev {}", server_ipv4, iface),
        format!("ip addr add {} dev {}", server_ipv6, iface),

        // Bring up the interface
        format!("ip link set {} up", iface),

        // Enable IP forwarding
        "sysctl -w net.ipv4.ip_forward=1".to_string(),
        "sysctl -w net.ipv6.conf.all.forwarding=1".to_string(),

        // IPv4 NAT rules
        format!("iptables -A FORWARD -i {} -o {} -j ACCEPT", iface, net_if),
        format!(
            "iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            net_if, iface
        ),
        format!("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", net_if),

        // IPv6 forwarding rules (no NAT typically)
        format!("ip6tables -A FORWARD -i {} -o {} -j ACCEPT", iface, net_if),
        format!(
            "ip6tables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
            net_if, iface
        ),
    ];

    for cmd in commands {
        run_command(&cmd)?;
    }

    Ok(())
}

pub fn route_all_traffic_through_tun(
    iface: &str,
    client_ipv4: &str,
    client_ipv6: &str,
) -> io::Result<()> {
    let commands = vec![
        // Delete existing default routes (ignore error with `|| true`)
        "ip route del default || true".to_string(),
        "ip -6 route del default || true".to_string(),

        // Create TUN interface (optional)
        // format!("ip tuntap add dev {} mode tun", iface),

        // Assign IP addresses to TUN interface
        // format!("ip addr add {} dev {}", client_ipv4, iface),
        format!("ip addr add {} dev {}", client_ipv6, iface),

        // Bring up the interface
        format!("ip link set {} up", iface),

        // Route all traffic through TUN
        format!("ip route add default dev {}", iface),
        // format!("ip -6 route add default dev {}", iface),
    ];

    for cmd in commands {
        run_command(&cmd)?;
    }

    Ok(())
}
