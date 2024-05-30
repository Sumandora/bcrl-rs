use std::rc::Rc;

use procfs::process::{MMPermissions, MMapPath};

use crate::cached_map::CachedMap;

type MapPredicate = dyn Fn(&CachedMap) -> bool;

#[derive(Clone)]
pub struct SearchConstraints {
    address_range: (usize, usize),
    predicates: Vec<Rc<MapPredicate>>,
    readable: Option<bool>,
    writable: Option<bool>,
    executable: Option<bool>,
}

impl SearchConstraints {
    pub fn get_address_range(&self) -> (usize, usize) {
        self.address_range
    }
    pub fn clamp_address_range(&self, address_range: (usize, usize)) -> (usize, usize) {
        let from = address_range.0.max(self.get_address_range().0) - address_range.0;
        let to = address_range.1.min(self.get_address_range().1) - address_range.0;

        (from, to)
    }
    pub fn get_readable(&self) -> Option<bool> {
        self.readable
    }
    pub fn get_writable(&self) -> Option<bool> {
        self.writable
    }
    pub fn get_executable(&self) -> Option<bool> {
        self.executable
    }

    pub fn everything() -> Self {
        SearchConstraints {
            address_range: (usize::min_value(), usize::max_value()),
            predicates: Vec::new(),
            readable: None,
            writable: None,
            executable: None,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.predicates
            .push(Rc::new(move |map| match &map.get_name() {
                MMapPath::Other(path) => path
                    .split('/')
                    .last()
                    .map(|other_name| other_name == name)
                    .unwrap_or(false),
                MMapPath::Path(path) => path
                    .file_name()
                    .and_then(|other_name| other_name.to_str().map(|other_name| other_name == name))
                    .unwrap_or(false),
                _ => false,
            }));

        self
    }

    pub fn from(mut self, value: usize) -> Self {
        self.address_range.0 = value;
        self.address_range.1 = self.address_range.1.max(self.address_range.0);

        self
    }

    pub fn to(mut self, value: usize) -> Self {
        self.address_range.1 = value;
        self.address_range.0 = self.address_range.0.min(self.address_range.1);

        self
    }

    pub fn thats_readable(mut self) -> Self {
        self.readable = Some(true);

        self
    }

    pub fn thats_not_readable(mut self) -> Self {
        self.readable = Some(false);

        self
    }

    pub fn thats_writable(mut self) -> Self {
        self.writable = Some(true);

        self
    }

    pub fn thats_not_writable(mut self) -> Self {
        self.writable = Some(false);

        self
    }

    pub fn thats_executable(mut self) -> Self {
        self.executable = Some(true);

        self
    }

    pub fn thats_not_executable(mut self) -> Self {
        self.executable = Some(false);

        self
    }

    pub fn allows_address(&self, address: usize) -> bool {
        self.address_range.0 >= address || self.address_range.1 <= address
    }

    pub fn allows_map(&self, map: &CachedMap) -> bool {
        for predicate in &self.predicates {
            if !(*predicate)(map) {
                return false;
            }
        }

        if self.address_range.1 < map.get_from_address()
            || self.address_range.1 < map.get_to_address()
        {
            return false;
        }

        if let Some(readable) = self.readable {
            if readable != map.get_permissions().contains(MMPermissions::READ) {
                return false;
            }
        }

        if let Some(writable) = self.writable {
            if writable != map.get_permissions().contains(MMPermissions::WRITE) {
                return false;
            }
        }

        if let Some(executable) = self.executable {
            if executable != map.get_permissions().contains(MMPermissions::EXECUTE) {
                return false;
            }
        }

        true
    }

    pub fn test(&self, map: &CachedMap) -> bool {
        for predicate in &self.predicates {
            if !(*predicate)(map) {
                return false;
            }
        }
        true
    }
}
