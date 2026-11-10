//! Account command owns arguments, execution, reports, and rendering.
pub(crate) mod args;
pub(crate) mod contact;
pub(crate) mod execute;
mod interaction;
mod output;
pub(crate) mod render;
pub(crate) mod report;
mod selection;

#[cfg(test)]
mod tests;
