//! IPv4 route table with deterministic longest-prefix selection.

use super::ip::Ipv4Addr;
use crate::mm::KVec;

pub const LOOPBACK_INTERFACE: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub interface: u16,
    pub metric: u32,
}

impl Route {
    #[must_use]
    pub const fn destination(self, target: Ipv4Addr) -> Ipv4Addr {
        match self.gateway {
            Some(gateway) => gateway,
            None => target,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    InvalidPrefix,
    Duplicate,
    NotFound,
}

pub struct RouteTable {
    entries: KVec<Route>,
}

impl RouteTable {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: KVec::new(),
        }
    }

    pub fn add(&mut self, mut route: Route) -> Result<(), RouteError> {
        if route.prefix_len > 32 {
            return Err(RouteError::InvalidPrefix);
        }
        route.network = route.network.masked(route.prefix_len);
        if self.entries.contains(&route) {
            return Err(RouteError::Duplicate);
        }
        self.entries.push(route);
        Ok(())
    }

    pub fn remove(&mut self, route: Route) -> Result<(), RouteError> {
        let Some(index) = self.entries.iter().position(|existing| *existing == route) else {
            return Err(RouteError::NotFound);
        };
        self.entries.swap_remove(index);
        Ok(())
    }

    /// Remove every route owned by an interface, returning the number removed.
    /// DHCP uses this before applying a renewed or replacement lease so stale
    /// connected/default routes cannot survive an address change.
    pub fn remove_interface(&mut self, interface: u16) -> usize {
        let before = self.entries.len();
        self.entries.retain(|route| route.interface != interface);
        before - self.entries.len()
    }

    #[must_use]
    pub fn lookup(&self, destination: Ipv4Addr) -> Option<Route> {
        self.entries
            .iter()
            .filter(|route| destination.matches_prefix(route.network, route.prefix_len))
            .min_by(|left, right| {
                right
                    .prefix_len
                    .cmp(&left.prefix_len)
                    .then_with(|| left.metric.cmp(&right.metric))
                    .then_with(|| left.interface.cmp(&right.interface))
            })
            .copied()
    }

    #[must_use]
    pub fn entries(&self) -> &[Route] {
        &self.entries
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}
