use std::{os::unix::fs::FileExt, rc::Rc};

use procfs::{
    process::{MemoryMaps, Process},
    ProcError,
};
use signature_scanner::Signature;

use std::fs::File;

use crate::{
    cached_map::CachedMap, cached_maps::CachedMaps, safe_pointer::SafePointer,
    search_constraints::SearchConstraints, session::Session,
};

#[derive(Debug)]
pub struct BcrlFactory {
    maps: Rc<CachedMaps>,
}

impl BcrlFactory {
    /// Creates a new BcrlFactory from a process
    pub fn from_process(process: &Process) -> Result<Self, ProcError> {
        let maps = process.maps()?;
        let mem_file = process.mem()?;

        Self::from_files(&maps, &mem_file)
    }

    /// Creates a new BcrlFactory from mappings and a /proc/$/mem file
    pub fn from_files(mappings: &MemoryMaps, mem_file: &File) -> Result<Self, ProcError> {
        let mut maps = CachedMaps::new();

        for map in mappings {
            let size = (map.address.1 - map.address.0) as usize;
            let mut memory = vec![0; size];
            if let Ok(length) = mem_file.read_at(memory.as_mut_slice(), map.address.0) {
                if length != size {
                    continue;
                }
                maps.insert(CachedMap::new(
                    map.address.0 as usize,
                    map.address.1 as usize,
                    map.perms,
                    map.pathname.clone(),
                    memory.into_boxed_slice(),
                ));
            }
        }

        Ok(BcrlFactory {
            maps: Rc::new(maps),
        })
    }

    /// Creates a Session with a signature
    pub fn signature(&self, pattern: Signature, constraints: SearchConstraints) -> Session<'_> {
        Session {
            pool: Box::new(self.maps.iter().flat_map(move |map| {
                if !constraints.allows_map(map) {
                    return Vec::new();
                }
                let (from, to) =
                    constraints.clamp_address_range((map.get_from_address(), map.get_to_address()));

                let bytes =
                    &map.get_bytes()[from - map.get_from_address()..to - map.get_from_address()];

                pattern
                    .all(bytes)
                    .map(move |offset| {
                        SafePointer::new(self.maps.clone(), map.get_from_address() + offset)
                    })
                    .collect::<Vec<_>>()
            })),
        }
    }

    /// Creates a Session with a list of pointers
    pub fn pointers<'a>(&'a self, pointers: impl Iterator<Item = usize> + 'a) -> Session<'a> {
        Session {
            pool: Box::new(pointers.map(|address| SafePointer::new(self.maps.clone(), address))),
        }
    }

    /// Creates a Session with a single pointer
    pub fn pointer(&self, pointer: usize) -> Session<'_> {
        Session {
            pool: Box::new([SafePointer::new(self.maps.clone(), pointer)].into_iter()),
        }
    }

    /// Get the internal caches that BCRL stores. You will likely never need this.
    pub fn get_cache(&self) -> Rc<CachedMaps> {
        self.maps.clone()
    }
}
