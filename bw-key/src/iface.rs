
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DEFAULT_IFACE: &str = "tailscale0";

pub const DEFAULT_PORT: u16 = 8787;

pub fn is_tailnet(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..128).contains(&o[1])
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

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
