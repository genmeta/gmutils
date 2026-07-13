use dhttp::name::DhttpName;
use rankey::EncodePem;
use snafu::ResultExt;

use crate::cli::{EncodeCsrSnafu, Error, GenerateCsrSnafu, GenerateKeySnafu};

pub(crate) trait KeyMaterialGenerator {
    fn generate_key(&self) -> Result<String, Error>;
    fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RankeyGenerator;

impl KeyMaterialGenerator for RankeyGenerator {
    fn generate_key(&self) -> Result<String, Error> {
        rankey::generate_secp384r1_key()
            .map(|key| key.to_string())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .context(GenerateKeySnafu)
    }

    fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error> {
        rankey::generate_csr(key_pem, "CN", full_name, &[full_name])
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .context(GenerateCsrSnafu)?
            .to_pem(rankey::LineEnding::LF)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .context(EncodeCsrSnafu)
    }
}

pub(crate) struct LazyKeyMaterial<G = RankeyGenerator> {
    name: DhttpName<'static>,
    generator: G,
    key_pem: Option<String>,
    csr_pem: Option<String>,
}

impl<G> LazyKeyMaterial<G>
where
    G: KeyMaterialGenerator,
{
    pub(crate) fn new(name: DhttpName<'_>, generator: G) -> Self {
        Self {
            name: name.into_owned(),
            generator,
            key_pem: None,
            csr_pem: None,
        }
    }

    pub(crate) fn ensure_key(&mut self) -> Result<&str, Error> {
        if self.key_pem.is_none() {
            self.key_pem = Some(super::progress::run_sync(
                super::progress::GENERATE_KEY,
                || self.generator.generate_key(),
            )?);
        }
        Ok(self
            .key_pem
            .as_deref()
            .expect("key material was generated above"))
    }

    pub(crate) fn csr_pem(&mut self) -> Result<&str, Error> {
        self.ensure_key()?;
        if self.csr_pem.is_none() {
            let csr = self.generator.generate_csr(
                self.key_pem
                    .as_deref()
                    .expect("key material was generated above"),
                self.name.as_full(),
            )?;
            self.csr_pem = Some(csr);
        }
        Ok(self
            .csr_pem
            .as_deref()
            .expect("CSR material was generated above"))
    }

    pub(crate) fn key_pem(&self) -> Option<&str> {
        self.key_pem.as_deref()
    }
}

impl LazyKeyMaterial<RankeyGenerator> {
    pub(crate) fn for_name(name: DhttpName<'_>) -> Self {
        Self::new(name, RankeyGenerator)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CountingGenerator {
        key_calls: Arc<AtomicUsize>,
        csr_calls: Arc<AtomicUsize>,
    }

    impl CountingGenerator {
        fn key_calls(&self) -> usize {
            self.key_calls.load(Ordering::SeqCst)
        }

        fn csr_calls(&self) -> usize {
            self.csr_calls.load(Ordering::SeqCst)
        }
    }

    impl KeyMaterialGenerator for CountingGenerator {
        fn generate_key(&self) -> Result<String, Error> {
            self.key_calls.fetch_add(1, Ordering::SeqCst);
            Ok("test-key".to_string())
        }

        fn generate_csr(&self, key_pem: &str, full_name: &str) -> Result<String, Error> {
            self.csr_calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("csr:{key_pem}:{full_name}"))
        }
    }

    #[test]
    fn lazy_material_generates_one_key_and_one_csr_across_retries() {
        let generator = CountingGenerator::default();
        let name = DhttpName::try_from("alice.smith").unwrap();
        let mut material = LazyKeyMaterial::new(name.borrow(), generator.clone());

        let first = material.csr_pem().unwrap().to_string();
        let second = material.csr_pem().unwrap().to_string();

        assert_eq!(first, second);
        assert_eq!(material.key_pem(), Some("test-key"));
        assert_eq!(generator.key_calls(), 1);
        assert_eq!(generator.csr_calls(), 1);
    }

    #[test]
    fn constructing_lazy_material_has_no_crypto_side_effect() {
        let generator = CountingGenerator::default();
        let name = DhttpName::try_from("alice.smith").unwrap();
        let _material = LazyKeyMaterial::new(name.borrow(), generator.clone());

        assert_eq!(generator.key_calls(), 0);
        assert_eq!(generator.csr_calls(), 0);
    }
}
