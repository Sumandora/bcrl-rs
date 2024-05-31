use procfs::process::MMapPath;
use signature_scanner::Signature;

use byteorder::ByteOrder;

use crate::{safe_pointer::SafePointer, search_constraints::SearchConstraints};

pub struct Session<'a> {
    pub(crate) pool: Box<dyn Iterator<Item = SafePointer> + 'a>,
}

impl<'a> Session<'a> {
    /// Steps forward through the process memory map.
    pub fn step_forwards(self, operand: usize) -> Self {
        self.mutate(move |ptr| {
            ptr.add(operand);
        })
    }

    /// Steps backwards through the process memory map.
    pub fn step_backwards(self, operand: usize) -> Self {
        self.mutate(move |ptr| {
            ptr.sub(operand);
        })
    }

    /// Dereferences each pointer in the pool.
    pub fn dereference<Endian: ByteOrder>(self) -> Self {
        self.mutate(move |ptr| {
            ptr.dereference::<Endian>();
        })
    }

    /// Dereferences relative addresses.
    pub fn relative_to_absolute<Endian: ByteOrder>(self) -> Self {
        self.mutate(move |ptr| {
            ptr.relative_to_absolute::<Endian>();
        })
    }

    /// Finds the previous occurrence of a signature.
    pub fn prev_occurrence(self, signature: Signature, constraints: SearchConstraints) -> Self {
        self.mutate(move |ptr| {
            ptr.prev_occurrence(&signature, &constraints);
        })
    }

    /// Finds the next occurrence of a signature.
    pub fn next_occurrence(self, signature: Signature, constraints: SearchConstraints) -> Self {
        self.mutate(move |ptr| {
            ptr.next_occurrence(&signature, &constraints);
        })
    }

    /// Jumps over the current instruction to the next one.
    pub fn next_instruction<Isa: lde::Isa>(self) -> Self {
        self.mutate(move |ptr| {
            ptr.next_instruction::<Isa>();
        })
    }

    /// Finds all references to the pointer.
    #[cfg(target_pointer_width = "64")]
    pub fn find_all_references<Endian: ByteOrder>(
        mut self,
        instruction_length: usize,
        constraints: SearchConstraints,
    ) -> Self {
        self.pool = Box::new(
            self.pool
                .flat_map(move |ptr| {
                    ptr.find_all_references::<Endian>(instruction_length, &constraints)
                        .collect::<Vec<_>>()
                })
                .filter(|ptr| !ptr.is_invalidated()),
        );

        self
    }

    /// Finds all relative references to the pointer
    #[cfg(target_pointer_width = "64")]
    pub fn find_relative_references<Endian: ByteOrder>(
        mut self,
        instruction_length: usize,
        constraints: SearchConstraints,
    ) -> Self {
        self.pool = Box::new(
            self.pool
                .flat_map(move |ptr| {
                    ptr.find_relative_references::<Endian>(instruction_length, &constraints)
                        .collect::<Vec<_>>()
                })
                .filter(|ptr| !ptr.is_invalidated()),
        );

        self
    }

    /// Finds all absolute references to the pointer.
    pub fn find_absolute_references<Endian: ByteOrder>(
        mut self,
        constraints: SearchConstraints,
    ) -> Self {
        self.pool = Box::new(
            self.pool
                .flat_map(move |ptr| {
                    ptr.find_absolute_references::<Endian>(&constraints)
                        .collect::<Vec<_>>()
                })
                .filter(|ptr| !ptr.is_invalidated()),
        );

        self
    }

    /// Filters the pool to only contain pointers that currently match the signature.
    pub fn signature_filter(mut self, signature: Signature) -> Self {
        self.pool = Box::new(self.pool.filter(move |ptr| ptr.does_match(&signature)));

        self
    }

    /// Filters the pool to only contain pointers that currently match the signature.
    pub fn filter_module(mut self, module_name: &'a str) -> Self {
        self.pool = Box::new(self.pool.filter(move |ptr| {
            ptr.get_module_name()
                .map(|module| match module {
                    MMapPath::Path(path) => path
                        .file_name()
                        .map(|file_name| file_name == module_name)
                        .unwrap_or(false),
                    MMapPath::Other(name) => name
                        .split('/')
                        .last()
                        .map(|file_name| file_name == module_name)
                        .unwrap_or(false),
                    _ => false,
                })
                .unwrap_or(false)
        }));

        self
    }

    /// Filters the pool using a custom filter function.
    pub fn filter<F>(mut self, mut f: F) -> Self
    where
        F: FnMut(&SafePointer) -> bool + 'a,
    {
        self.pool = Box::new(self.pool.filter(move |ptr| f(ptr)));

        self
    }

    /// Mutates the pool using a custom mutator function.
    pub fn mutate<F>(mut self, mut f: F) -> Self
    where
        F: FnMut(&mut SafePointer) + 'a,
    {
        self.pool = Box::new(
            self.pool
                .map(move |mut ptr| {
                    f(&mut ptr);
                    ptr
                })
                .filter(|ptr| !ptr.is_invalidated()),
        );

        self
    }

    /// Repeats the mutation n times.
    pub fn repeat_n<F>(self, iterations: usize, mut f: F) -> Self
    where
        F: FnMut(&mut SafePointer) + 'a,
    {
        self.mutate(move |ptr| {
            for _ in 0..iterations {
                f(ptr);
            }
        })
    }

    /// Repeats the mutation while the custom mutator function returns true.
    pub fn repeat_while<F>(self, mut f: F) -> Self
    where
        F: FnMut(&mut SafePointer) -> bool + 'a,
    {
        self.mutate(move |ptr| while f(ptr) {})
    }

    /// Maps the pool using a custom mapper function.
    pub fn map<F>(mut self, f: F) -> Self
    where
        F: FnMut(SafePointer) -> SafePointer + 'static,
    {
        self.pool = Box::new(self.pool.map(f));

        self
    }

    /// For each element in the pool, executes a custom function.
    pub fn inspect<F>(mut self, f: F) -> Self
    where
        F: FnMut(&SafePointer) + 'static,
    {
        self.pool = Box::new(self.pool.inspect(f));

        self
    }

    /// Returns the last element, that's left in the pool. When multiple/no pointers are left then the count is returned.
    pub fn get_pointer(mut self) -> Result<usize, usize> {
        let result = self.pool.next();
        let count = self.pool.count();

        if let Some(res) = result {
            if count == 0 {
                return Ok(res.get_address());
            }
        }

        Err(count + 1 /* Just read the first from the iterator */)
    }

    /// Returns the pool as an iterator.
    pub fn get_pool(self) -> impl Iterator<Item = usize> + 'a {
        self.pool.map(|ptr| ptr.get_address())
    }
}
