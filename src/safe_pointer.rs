use std::rc::Rc;

use byteorder::ByteOrder;
use procfs::process::MMapPath;
use signature_scanner::Signature;

use crate::cached_maps::CachedMaps;
use crate::cached_maps::FindAddress;

use crate::search_constraints::SearchConstraints;

use x86_xref::*;

#[derive(Clone, Debug)]
pub struct SafePointer {
    maps: Rc<CachedMaps>,
    address: usize,
    invalid: bool,
}

impl Eq for SafePointer {}

impl PartialEq for SafePointer {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl std::hash::Hash for SafePointer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl SafePointer {
    pub fn new(maps: Rc<CachedMaps>, address: usize) -> Self {
        Self {
            maps,
            address,
            invalid: false,
        }
    }

    pub fn add(&mut self, operand: usize) -> &mut Self {
        self.address += operand;

        self
    }

    pub fn sub(&mut self, operand: usize) -> &mut Self {
        self.address -= operand;

        self
    }

    pub fn dereference<Endian: ByteOrder>(&mut self) -> &mut Self {
        if let Some(bytes) = self.read(std::mem::size_of::<usize>()) {
            if cfg!(target_pointer_width = "64") {
                self.address = Endian::read_u64(bytes) as usize;
            } else {
                self.address = Endian::read_u32(bytes) as usize;
            }
        } else {
            self.invalidate();
        }

        self
    }

    #[cfg(target_pointer_width = "64")]
    pub fn relative_to_absolute<Endian: ByteOrder>(&mut self) -> &mut Self {
        let i32_size = std::mem::size_of::<i32>();
        if let Some(offset_bytes) = self.read(i32_size) {
            let offset = Endian::read_i32(offset_bytes);

            self.address += i32_size;

            use std::cmp::Ordering;
            match offset.cmp(&0) {
                Ordering::Greater => self.address += offset as usize,
                Ordering::Less => self.address -= offset.unsigned_abs() as usize,
                Ordering::Equal => {}
            }
        } else {
            self.invalidate();
        }

        self
    }

    pub fn revalidate(&mut self) -> &mut Self {
        self.invalid = false;

        self
    }

    pub fn invalidate(&mut self) -> &mut Self {
        self.invalid = true;

        self
    }

    pub fn prev_occurrence(
        &mut self,
        signature: &Signature,
        constraints: &SearchConstraints,
    ) -> &mut Self {
        let map = self.maps.find_map(self.address);
        if map.is_none() {
            return self.invalidate();
        }
        let map = map.unwrap();

        if !constraints.allows_map(map) {
            return self.invalidate();
        }

        let range = constraints.clamp_address_range((map.get_from_address(), self.address));

        if let Some(hit) = signature.prev(
            &map.get_bytes()[range.0 - map.get_from_address()..range.1 - map.get_from_address()],
        ) {
            self.address -= hit;
            return self;
        }

        self.invalidate()
    }

    pub fn next_occurrence(
        &mut self,
        signature: &Signature,
        constraints: &SearchConstraints,
    ) -> &mut Self {
        let map = self.maps.find_map(self.address);
        if map.is_none() {
            return self.invalidate();
        }
        let map = map.unwrap();

        let range = constraints.clamp_address_range((self.address, map.get_to_address()));

        if let Some(hit) = signature.next(
            &map.get_bytes()[range.0 - map.get_from_address()..range.1 - map.get_to_address()],
        ) {
            self.address += hit;
            return self;
        }

        self.invalidate()
    }

    pub fn next_instruction<Isa: lde::Isa>(&mut self) -> &mut Self {
        let map = self.maps.find_map(self.address);
        if map.is_none() {
            return self.invalidate();
        }
        let map = map.unwrap();

        let bytes = &map.get_bytes()[self.address - map.get_from_address()..map.get_size()];

        let len = Isa::ld(bytes);

        if len == 0 {
            return self.invalidate();
        }

        self.address += len as usize;

        self
    }

    #[cfg(target_pointer_width = "64")]
    pub fn find_all_references<'a, Endian: ByteOrder>(
        &'a self,
        instruction_length: usize,
        constraints: &'a SearchConstraints,
    ) -> impl Iterator<Item = SafePointer> + 'a {
        self.maps
            .iter()
            .filter(|map| constraints.allows_map(map))
            .flat_map(move |map| {
                let (from, to) =
                    constraints.clamp_address_range((map.get_from_address(), map.get_to_address()));

                let bytes =
                    &map.get_bytes()[from - map.get_from_address()..to - map.get_from_address()];

                let searcher = RelativeAndAbsoluteFinder::<Endian>::new(
                    map.get_from_address(),
                    instruction_length,
                    self.address,
                );

                searcher
                    .all(bytes)
                    .map(|offset| {
                        SafePointer::new(self.maps.clone(), offset + map.get_from_address())
                    })
                    .collect::<Vec<_>>()
            })
    }

    #[cfg(target_pointer_width = "64")]
    pub fn find_relative_references<'a, Endian: ByteOrder>(
        &'a self,
        instruction_length: usize,
        constraints: &'a SearchConstraints,
    ) -> impl Iterator<Item = SafePointer> + 'a {
        self.maps
            .iter()
            .filter(|map| constraints.allows_map(map))
            .flat_map(move |map| {
                let (from, to) =
                    constraints.clamp_address_range((map.get_from_address(), map.get_to_address()));

                let bytes =
                    &map.get_bytes()[from - map.get_from_address()..to - map.get_from_address()];

                let searcher = RelativeFinder::<Endian>::new(
                    map.get_from_address(),
                    instruction_length,
                    self.address,
                );

                searcher
                    .all(bytes)
                    .map(|offset| {
                        SafePointer::new(self.maps.clone(), offset + map.get_from_address())
                    })
                    .collect::<Vec<_>>()
            })
    }

    pub fn find_absolute_references<'a, Endian: ByteOrder>(
        &'a self,
        constraints: &'a SearchConstraints,
    ) -> impl Iterator<Item = SafePointer> + 'a {
        self.maps
            .iter()
            .filter(|map| constraints.allows_map(map))
            .flat_map(move |map| {
                let (from, to) =
                    constraints.clamp_address_range((map.get_from_address(), map.get_to_address()));

                let bytes =
                    &map.get_bytes()[from - map.get_from_address()..to - map.get_from_address()];

                let searcher = AbsoluteFinder::<Endian>::new(self.address);

                searcher
                    .all(bytes)
                    .map(|offset| {
                        SafePointer::new(self.maps.clone(), offset + map.get_from_address())
                    })
                    .collect::<Vec<_>>()
            })
    }

    pub fn does_match(&self, signature: &Signature) -> bool {
        let bytes = self.read(signature.get_elements().len());

        bytes.is_some() && signature.matches(bytes.unwrap())
    }

    pub fn get_address(&self) -> usize {
        self.address
    }

    pub fn is_invalidated(&self) -> bool {
        self.invalid
    }

    pub fn is_valid(&self, length: usize) -> bool {
        if self.invalid {
            return false;
        }
        let region = self.maps.find_map(self.address);
        if region.is_none() {
            return false;
        }
        let region = region.unwrap();

        region.get_to_address() - self.address >= length
    }

    pub fn read(&self, length: usize) -> Option<&[u8]> {
        if !self.is_valid(length) {
            return None;
        }

        let region = self.maps.find_map(self.address)?;
        let offset = self.address - region.get_from_address();

        Some(&region.get_bytes()[offset..offset + length])
    }

    pub fn get_module_name(&self) -> Option<&MMapPath> {
        let region = self.maps.find_map(self.address)?;
        Some(region.get_name())
    }
}
