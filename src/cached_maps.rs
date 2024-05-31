use std::collections::BinaryHeap;

use crate::cached_map::CachedMap;

pub type CachedMaps = BinaryHeap<CachedMap>;

pub trait FindAddress {
    fn find_map(&self, address: usize) -> Option<&CachedMap>;
}

impl FindAddress for CachedMaps {
    fn find_map(&self, address: usize) -> Option<&CachedMap> {
        self.iter().find(|map| map.contains(address))
    }
}
