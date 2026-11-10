use anyhow::bail;
use fedimint_portalloc::port_alloc;

/// Number of ports [`super::Global::init`] takes from its [`PortRange`] when
/// none of them are provided explicitly (gateway base port, faucet port).
///
/// Keep in sync with the `ports.take(..)` calls in [`super::Global`]. A value
/// that is too small makes devimint fail on startup.
pub const GLOBAL_PORTS: u16 = 24;

/// A contiguous range of ports reserved with a single [`port_alloc`] call and
/// handed out one by one.
///
/// Each [`port_alloc`] call takes a lock shared by every test process on the
/// machine. Reserving all ports at once keeps devimint startup from queueing
/// on that lock once per port when many tests run in parallel.
#[derive(Debug)]
pub struct PortRange {
    next: u16,
    end: u16,
}

impl PortRange {
    /// Reserve `size` ports with [`port_alloc`].
    pub fn alloc(size: u16) -> anyhow::Result<Self> {
        Ok(Self::from_base(port_alloc(size)?, size))
    }

    /// Use `size` ports starting at `base` without reserving them.
    pub fn from_base(base: u16, size: u16) -> Self {
        Self {
            next: base,
            end: base.saturating_add(size),
        }
    }

    /// Take the next `count` contiguous ports and return the first of them.
    pub fn take(&mut self, count: u16) -> anyhow::Result<u16> {
        let start = self.next;
        let Some(end) = start.checked_add(count).filter(|end| *end <= self.end) else {
            let left = self.end - start;
            bail!("Port range exhausted: {count} ports requested, {left} left");
        };
        self.next = end;
        Ok(start)
    }
}

#[cfg(test)]
mod tests;
