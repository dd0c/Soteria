//! Integrity engine: inventory scans, baseline creation, approval, sealing,
//! verification and comparison (FR-005..FR-008, FR-015, FR-044, SRS 10.3).

pub mod baseline;
pub mod compare;
pub mod keys;
mod rows;
pub mod scan;
