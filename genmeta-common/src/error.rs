use snafu::Snafu;

pub type AnyError = dyn std::error::Error + Send + Sync + 'static;
pub type BoxError = Box<AnyError>;

#[derive(Debug, Snafu)]
#[snafu(whatever)]
#[snafu(display("{message}"))]
#[snafu(provide(opt, ref, chain, AnyError => source.as_deref()))]
pub struct Whatever {
    #[snafu(source(from(BoxError, Some)))]
    #[snafu(provide(false))]
    source: Option<BoxError>,
    message: String,
    backtrace: snafu::Backtrace,
}
