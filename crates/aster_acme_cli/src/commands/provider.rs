//! Manage provider profiles with explicit input, execution, report and presentation owners.
pub(crate) mod args;
pub(crate) mod execute;
mod interaction;
pub(crate) mod render;
pub(crate) mod report;
pub(crate) mod runtime;

#[cfg(test)]
mod tests;
