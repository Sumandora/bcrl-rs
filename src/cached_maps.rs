use std::collections::BinaryHeap;

use crate::cached_map::CachedMap;

pub type CachedMaps = BinaryHeap<CachedMap>;

pub trait FindAddress {
    fn find_map(&self, address: usize) -> Option<&CachedMap>;
}

impl FindAddress for CachedMaps {
    fn find_map(&self, address: usize) -> Option<&CachedMap> {
        if self.is_empty() {
            return None;
        }

        self.iter().find(|map| map.contains(address))
    }
}
