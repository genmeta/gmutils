use std::str::FromStr;

/// Wrapper that formats parse errors with [`snafu::Report`] for multi-line
/// error chain display in clap argument parsing.
///
/// Use as a clap argument type to get richer error messages when parsing
/// complex types like [`LocationPattern`] or [`Name`]:
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Cli {
///     pattern: ReportFromStr<LocationPattern>,
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ReportFromStr<T>(pub T);

#[derive(Debug, snafu::Snafu)]
#[snafu(display("{}", snafu::Report::from_error(source)))]
pub struct ReportError<E: std::error::Error + 'static> {
    #[snafu(source(false))]
    source: E,
}

impl<T> FromStr for ReportFromStr<T>
where
    T: FromStr<Err: std::error::Error + 'static>,
{
    type Err = ReportError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        T::from_str(s)
            .map(Self)
            .map_err(|source| ReportError { source })
    }
}
