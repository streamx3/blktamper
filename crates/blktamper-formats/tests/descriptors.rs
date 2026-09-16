//! Descriptor self-consistency.
//!
//! A transcribed offset table has one common failure mode: an offset or width that
//! is off by a few. This test catches essentially all of it the moment a descriptor
//! is added, which is worth more than proofreading (doc/06-format-scope.md).

use blktamper_core::validate_desc;

#[test]
fn every_descriptor_tiles_its_record_exactly() {
    let mut problems = Vec::new();
    for d in blktamper_formats::all_descriptors() {
        for e in validate_desc(d) {
            problems.push(e);
        }
    }
    assert!(problems.is_empty(), "descriptor problems:\n  {}", problems.join("\n  "));
}

#[test]
fn every_descriptor_documents_every_field() {
    let mut bare = Vec::new();
    for d in blktamper_formats::all_descriptors() {
        for f in d.fields {
            if f.doc.trim().is_empty() {
                bare.push(format!("{}.{}", d.name, f.name));
            }
        }
        if d.spec.trim().is_empty() {
            bare.push(format!("{} has no spec reference", d.name));
        }
    }
    assert!(bare.is_empty(), "undocumented:\n  {}", bare.join("\n  "));
}

#[test]
fn descriptor_names_are_unique_within_the_build() {
    let mut names: Vec<&str> = blktamper_formats::all_descriptors().iter().map(|d| d.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two descriptors share a name");
}
