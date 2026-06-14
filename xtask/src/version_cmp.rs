use std::{cmp::Ordering, str::FromStr};

use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum CompareVersionError {
    #[snafu(display("failed to parse deb version {value}"))]
    DebParse {
        value: String,
        source: debversion::ParseError,
    },
}

pub fn compare_deb_versions(left: &str, right: &str) -> Result<Ordering, CompareVersionError> {
    let left =
        debversion::Version::from_str(left).context(compare_version_error::DebParseSnafu {
            value: left.to_string(),
        })?;
    let right =
        debversion::Version::from_str(right).context(compare_version_error::DebParseSnafu {
            value: right.to_string(),
        })?;
    Ok(left.cmp(&right))
}

pub fn compare_rpm_versions(left: &str, right: &str) -> Result<Ordering, CompareVersionError> {
    Ok(rpm_version::Evr::parse(left).cmp(&rpm_version::Evr::parse(right)))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::{compare_deb_versions, compare_rpm_versions};

    #[test]
    fn compares_deb_versions_with_dpkg_ordering() {
        assert_eq!(
            compare_deb_versions("1.8.10-1", "1.8.9-1").expect("deb version should parse"),
            Ordering::Greater,
        );
    }

    #[test]
    fn compares_rpm_versions_with_rpm_ordering() {
        assert_eq!(
            compare_rpm_versions("1.8.10-1", "1.8.9-1").expect("rpm version should parse"),
            Ordering::Greater,
        );
    }
}
