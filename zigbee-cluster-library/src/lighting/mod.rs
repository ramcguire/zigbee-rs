//! Lighting
//!
//! See Section 5
//!
//! Generic lighting interfaces

pub mod color_control;
pub mod level_control;
pub mod on_off;

pub use color_control::ColorControlServer;
pub use level_control::LevelControlServer;
pub use on_off::OnOffServer;
