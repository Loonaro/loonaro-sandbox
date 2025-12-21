//! Network IOC collection configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCollectionConfig {
    pub enabled: bool,
    pub track_dns: bool,
    pub track_tcp: bool,
    pub track_udp: bool,
    pub track_http: bool,
    pub track_https: bool,
    pub always_track_ports: Vec<u16>,
    pub ignore_ports: Vec<u16>,
    pub ignore_ips: Vec<String>,
    pub ignore_domains: Vec<String>,
    pub external_only: bool,
}

impl Default for NetworkCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_dns: true,
            track_tcp: true,
            track_udp: true,
            track_http: true,
            track_https: true,
            always_track_ports: vec![
                80, 443, 8080, 8443, 21, 22, 23, 25, 465, 587, 53, 3389, 4444, 5555, 6666,
            ],
            ignore_ports: vec![],
            ignore_ips: vec!["127.0.0.1".into(), "::1".into()],
            ignore_domains: vec!["localhost".into(), "*.local".into()],
            external_only: false,
        }
    }
}

impl NetworkCollectionConfig {
    pub fn should_track_connection(&self, dest_ip: &str, dest_port: u16, protocol: &str) -> bool {
        if !self.enabled {
            return false;
        }
        match protocol.to_lowercase().as_str() {
            "tcp" if !self.track_tcp => return false,
            "udp" if !self.track_udp => return false,
            "http" if !self.track_http => return false,
            "https" if !self.track_https => return false,
            _ => {}
        }
        if self.ignore_ips.iter().any(|ip| ip == dest_ip) {
            return false;
        }
        if self.ignore_ports.contains(&dest_port) {
            return false;
        }
        if self.always_track_ports.contains(&dest_port) {
            return true;
        }
        if self.external_only && Self::is_internal_ip(dest_ip) {
            return false;
        }
        true
    }

    pub fn should_track_dns(&self, domain: &str) -> bool {
        if !self.enabled || !self.track_dns {
            return false;
        }
        let domain_lower = domain.to_lowercase();
        for ignored in &self.ignore_domains {
            if ignored.starts_with("*.") {
                let suffix = &ignored[2..];
                if domain_lower.ends_with(suffix) {
                    return false;
                }
            } else if domain_lower == ignored.to_lowercase() {
                return false;
            }
        }
        true
    }

    fn is_internal_ip(ip: &str) -> bool {
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("127.")
            || ip == "::1"
    }
}
