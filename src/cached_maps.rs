use std::collections::BinaryHeap;

use bound_stl::UpperBound;

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
        let it = self.upper_bound_by_key(&address, |e| e.get_from_address());
        if let Ok(idx) = it {
            if idx > 0 {
                let map = self.iter().nth(idx - 1)?;

                if map.get_from_address() >= address && address <= map.get_to_address() {
                    return Some(map);
                }
            }
        }

        None
    }
}
