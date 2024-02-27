use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {}

// TODO: Boilerplate-code
impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
