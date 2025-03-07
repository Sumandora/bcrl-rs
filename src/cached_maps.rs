use std::collections::BTreeSet;

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

        // TODO: use binary search here.
        self.iter().find(|map| map.contains(address))
    }
}
