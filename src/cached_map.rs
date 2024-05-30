use procfs::process::{MMPermissions, MMapPath};

#[derive(Eq, Debug)]
pub struct CachedMap {
    from_address: usize,
    to_address: usize,
    permissions: MMPermissions,
    name: MMapPath,
    bytes: Box<[u8]>,
}

impl CachedMap {
    pub fn new(
        from_address: usize,
        to_address: usize,
        permissions: MMPermissions,
        name: MMapPath,
        bytes: Box<[u8]>,
    ) -> Self {
        Self {
            from_address,
            to_address,
            permissions,
            name,
            bytes,
        }
    }

    pub fn get_from_address(&self) -> usize {
        self.from_address
    }
    pub fn get_to_address(&self) -> usize {
        self.to_address
    }
    pub fn get_size(&self) -> usize {
        self.to_address - self.from_address
    }
    pub fn get_permissions(&self) -> MMPermissions {
        self.permissions
    }
    pub fn get_name(&self) -> &MMapPath {
        &self.name
    }
    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn contains(&self, address: usize) -> bool {
        self.from_address >= address && address <= self.to_address
    }
}

impl std::cmp::PartialEq for CachedMap {
    fn eq(&self, other: &Self) -> bool {
        self.from_address == other.from_address
    }
}

impl PartialOrd for CachedMap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.from_address.cmp(&other.from_address))
    }
}

impl Ord for CachedMap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.from_address.cmp(&other.from_address)
    }
}
