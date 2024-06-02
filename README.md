# bcrl-rs

An advanced signature scanning library for Linux systems.

## Features:
- IDA signatures
- String signatures
- Cross references
- Builder pattern
- Easy to use

## Usage:

```rust
use bcrl_rs::*;
use byteorder::NativeEndian;
use signature_scanner::Signature;
use procfs::process::Process;

let process = Process::myself().unwrap();
let factory = BcrlFactory::from_process(&process).unwrap();

// Create with a signature;
factory.signature(Signature::ida("12 34 56 78 90 AB CD EF"), SearchConstraints::everything());

// Create with a string
factory.signature(Signature::string("Hello, world!", /*include_terminator:*/ false), SearchConstraints::everything());

// Create with a list of pointers
factory.pointers(vec![0x123usize, 0x456, 0x789].into_iter());

// Create with a single pointer
factory.pointer(0x123usize);

// Step forwards
session.step_forwards(123);

// Step backwards
session.step_backwards(123);

// Dereference each pointer
session.dereference::<NativeEndian>();

// Dereference relative addresses
session.relative_to_absolute::<NativeEndian>();

// Find the previous occurrence of a signature
session.prev_occurrence(Signature::string("Hello, world!", false), SearchConstraints::everything());

// Find the next occurrence of a signature
session.next_occurrence(Signature::string("Hello, world!", false), SearchConstraints::everything());

// Skip an instruction
session.next_instruction::<lde::X64>();

// Find all cross references
session.find_all_references::<NativeEndian>(/*instruction_length:*/ 4, SearchConstraints::everything());

// Find all relative references
session.find_relative_references::<NativeEndian>(/*instruction_length:*/ 4, SearchConstraints::everything());

// Find all absolute references
session.find_absolute_references::<NativeEndian>(SearchConstraints::everything());

// Filter the pool by signature
session.signature_filter(Signature::ida("AB CD EF"));

// Filter the pool by containing module
session.filter_module("libcurl.so");

// And more...
```
