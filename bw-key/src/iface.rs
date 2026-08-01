//! Resolving a listen address from an interface name.
//!
//! §5.1 requires binding to the tailnet interface and never to a wildcard. The
//! address behind that interface is per-host, so requiring the operator to copy
//! a 100.x literal into the unit file is exactly the friction that tempts a
//! `0.0.0.0` workaround. Naming the interface removes the literal without
//! widening what gets bound.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Tailscale's default interface name on Linux. macOS and the BSDs assign a
/// `utun*` whose number is not stable, so there the name must be given.
pub const DEFAULT_IFACE: &str = "tailscale0";

/// Matches the port `docs/bw-keyd.service` has always used. Arbitrary and
/// unregistered: the port carries no security weight — the interface bind and
/// the Noise handshake do — so it only needs to not collide.
pub const DEFAULT_PORT: u16 = 8787;

/// Tailscale allocates from 100.64.0.0/10 (CGNAT, RFC 6598) and
/// fd7a:115c:a1e0::/48.
pub fn is_tailnet(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..128).contains(&o[1])
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// Every IPv4/IPv6 address currently assigned to `iface`. An empty result and a
/// missing interface are deliberately the same case: both mean "not up yet".
pub fn addrs_of(iface: &str) -> Result<Vec<IpAddr>, String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(format!("getifaddrs: {}", std::io::Error::last_os_error()));
    }

    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != iface.as_bytes() {
            continue;
        }
        if let Some(ip) = unsafe { from_sockaddr(ifa.ifa_addr) } {
            out.push(ip);
        }
    }

    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// The address to bind on `iface`: tailnet IPv4 first, tailnet IPv6 second.
///
/// Addresses outside the tailnet ranges are ignored rather than used as a
/// fallback. An interface that merely shares the name is not the one §5.1 means,
/// and binding it would silently widen exposure.
pub fn tailnet_addr(iface: &str) -> Result<IpAddr, String> {
    let addrs = addrs_of(iface)?;
    if addrs.is_empty() {
        return Err(format!(
            "interface {iface} has no address — is tailscaled up and logged in?"
        ));
    }
    addrs
        .iter()
        .find(|a| a.is_ipv4() && is_tailnet(a))
        .or_else(|| addrs.iter().find(|a| is_tailnet(a)))
        .copied()
        .ok_or_else(|| {
            let found: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            format!(
                "interface {iface} has no tailnet address (found {}); \
                 pass --bind ADDR:PORT if this is deliberate",
                found.join(", ")
            )
        })
}

/// `sockaddr` is a prefix of the family-specific structs; the kernel guarantees
/// the tail is present for the family it reports. Read unaligned: nothing
/// promises `ifa_addr` meets `sockaddr_in6`'s alignment.
unsafe fn from_sockaddr(sa: *const libc::sockaddr) -> Option<IpAddr> {
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let s = std::ptr::read_unaligned(sa as *const libc::sockaddr_in);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let s = std::ptr::read_unaligned(sa as *const libc::sockaddr_in6);
            Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailnet_ranges_are_recognised() {
        for ok in ["100.64.0.1", "100.100.100.100", "100.127.255.255"] {
            assert!(is_tailnet(&ok.parse().unwrap()), "{ok}");
        }
        assert!(is_tailnet(&"fd7a:115c:a1e0::1".parse().unwrap()));
    }

    #[test]
    fn neighbouring_ranges_are_not_tailnet() {
        // 100.63/100.128 sit just outside the /10; the second octet check is
        // the whole boundary, so both sides of it are worth pinning.
        for bad in [
            "100.63.255.255",
            "100.128.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "0.0.0.0",
        ] {
            assert!(!is_tailnet(&bad.parse().unwrap()), "{bad}");
        }
        for bad in ["fd7a:115c:a1e1::1", "fe80::1", "::1"] {
            assert!(!is_tailnet(&bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn loopback_resolves_through_getifaddrs() {
        // Names differ (lo on Linux, lo0 on macOS), so try both and accept
        // whichever exists: the point is that parsing sockaddrs works at all.
        let addrs: Vec<IpAddr> = ["lo", "lo0"]
            .iter()
            .filter_map(|n| addrs_of(n).ok())
            .flatten()
            .collect();
        assert!(
            addrs.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()),
            "expected loopback in {addrs:?}"
        );
    }

    #[test]
    fn a_missing_interface_is_an_error_not_a_fallback() {
        assert!(tailnet_addr("definitely-not-an-interface").is_err());
    }
}
