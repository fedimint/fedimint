use strum_macros::EnumIter;

// #[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
