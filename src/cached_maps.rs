use std::collections::BTreeSet;

use bound_stl::UpperBound;

use crate::cached_map::CachedMap;

pub type CachedMaps = BTreeSet<CachedMap>;

pub trait FindAddress {
    fn find_map(&self, address: usize) -> Option<&CachedMap>;
}

impl FindAddress for CachedMaps {
    fn find_map(&self, address: usize) -> Option<&CachedMap> {
        if self.is_empty() {
            return None;
        }

        if let Ok(it) = self.upper_bound_by_key(&address, |map| map.get_from_address()) {
            if it > 0 {
                if let Some(reg) = self.iter().nth(it - 1) {
                    if reg.contains(address) {
                        return Some(reg);
                    }
                }
            }
        }

        None
    }
}
