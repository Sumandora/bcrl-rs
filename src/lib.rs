//! # bcrl-rs
//!
//! An advanced signature scanning library for Linux systems.
//!
//! ## Features:
//! - IDA signatures
//! - String signatures
//! - Cross references
//! - Builder pattern
//! - Easy to use
//!
//! ## Usage:
//!
//! ```rust
//! use bcrl_rs::*;
//! use byteorder::NativeEndian;
//! use signature_scanner::Signature;
//! use procfs::process::Process;
//!
//! let process = Process::myself().unwrap();
//! let factory = BcrlFactory::from_process(&process).unwrap();
//!
//! // Create with a signature;
//! factory.signature(Signature::ida("12 34 56 78 90 AB CD EF"), SearchConstraints::everything());
//!
//! // Create with a string
//! factory.signature(Signature::string("Hello, world!", /*include_terminator:*/ false), SearchConstraints::everything());
//!
//! // Create with a list of pointers
//! factory.pointers(vec![0x123usize, 0x456, 0x789].into_iter());
//!
//! // Create with a single pointer
//! factory.pointer(0x123usize);
//!
//! // Step forwards
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.step_forwards(123);
//!
//! // Step backwards
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.step_backwards(123);
//!
//! // Dereference each pointer
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.dereference::<NativeEndian>();
//!
//! // Dereference relative addresses
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.relative_to_absolute::<NativeEndian>();
//!
//! // Find the previous occurrence of a signature
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.prev_occurrence(Signature::string("Hello, world!", false), SearchConstraints::everything());
//!
//! // Find the next occurrence of a signature
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.next_occurrence(Signature::string("Hello, world!", false), SearchConstraints::everything());
//!
//! // Skip an instruction
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.next_instruction::<lde::X64>();
//!
//! // Find all cross references
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.find_all_references::<NativeEndian>(/*instruction_length:*/ 4, SearchConstraints::everything());
//!
//! // Find all relative references
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.find_relative_references::<NativeEndian>(/*instruction_length:*/ 4, SearchConstraints::everything());
//!
//! // Find all absolute references
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.find_absolute_references::<NativeEndian>(SearchConstraints::everything());
//!
//! // Filter the pool by signature
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.signature_filter(Signature::ida("AB CD EF"));
//!
//! // Filter the pool by containing module
//! # let session = factory.pointers(Vec::<usize>::new().into_iter());
//! session.filter_module("libcurl.so");
//!
//! // And more...
//! ```

pub mod cached_map;
pub mod cached_maps;
pub mod factory;
pub mod safe_pointer;
pub mod search_constraints;
pub mod session;

pub use factory::BcrlFactory;
pub use search_constraints::SearchConstraints;

#[cfg(test)]
mod tests {
    use byteorder::NativeEndian;
    use procfs::process::Process;
    use signature_scanner::Signature;

    use crate::{BcrlFactory, SearchConstraints};

    #[allow(dead_code)]
    fn find_me() {
        println!("Hello, world!");
    }

    #[test]
    fn test_search() {
        let process = Process::myself().unwrap();
        let factory = BcrlFactory::from_process(&process).unwrap();

        assert!(factory
            .signature(
                Signature::string("Hello, world!", false),
                SearchConstraints::everything().thats_readable(),
            )
            .find_all_references::<NativeEndian>(
                4,
                SearchConstraints::everything()
                    .thats_executable()
                    .thats_readable(),
            )
            .get_pool()
            .count() > 0);
    }
}
