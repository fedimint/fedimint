use lazy_static::lazy_static;
use semver::Version;

lazy_static! {
    pub static ref VERSION_0_3_0_ALPHA: Version =
        Version::parse("0.3.0-alpha").expect("version is parsable");
    pub static ref VERSION_0_3_0: Version = Version::parse("0.3.0").expect("version is parsable");
}
