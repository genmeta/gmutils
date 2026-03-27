use std::{
    fmt::Display,
    ops::ControlFlow,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::fs;
use toml::Spanned;

use crate::{
    GenmetaHome,
    identity::{self, IdentityHome, Name},
};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    pub name: Option<Spanned<Name<'static>>>,
}

impl DefaultConfig {
    pub fn name(&self) -> Option<&Name<'static>> {
        self.name.as_ref().map(|spanned| spanned.as_ref())
    }

    pub fn set_name(&mut self, name: Name<'static>) {
        let span = match &self.name {
            Some(spanned) => spanned.span(),
            None => 0..0,
        };
        self.name = Some(Spanned::new(span, name));
    }
}

impl DefaultConfig {
    pub const FILE_NAME: &'static str = "default.toml";
}

#[derive(Debug)]
pub struct DefaultConfigFile {
    path: PathBuf,
    content: Option<String>,
    config: DefaultConfig,
}

#[derive(Debug, Clone, Copy)]
struct LineCol {
    line: usize,
    column: usize,
}

impl LineCol {
    fn locate(source: &str, offset: usize) -> LineCol {
        let fold = |last: LineCol, (index, char)| {
            let current = match char {
                '\n' => LineCol {
                    line: last.line + 1,
                    column: 1,
                },
                _ => LineCol {
                    line: last.line,
                    column: last.column + 1,
                },
            };
            if index == offset {
                ControlFlow::Break(current)
            } else {
                ControlFlow::Continue(current)
            }
        };
        let (ControlFlow::Continue(line_col) | ControlFlow::Break(line_col)) =
            (source.chars().enumerate()).try_fold(LineCol { line: 1, column: 1 }, fold);
        line_col
    }
}

impl Display for LineCol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[derive(Debug)]
struct FileLineCol {
    path: PathBuf,
    line_col: LineCol,
}

impl Display for FileLineCol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.path.display(), self.line_col)
    }
}

#[derive(Snafu, Debug)]
#[snafu(module, display(
    "failed to load identity specified{}",
    config.as_ref().map_or(String::new(), |loc| format!(" at {loc}"))
))]
pub struct LoadIdentityError {
    config: Option<FileLineCol>,
    source: identity::fs::LoadIdentityError,
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadDefaultConfigError {
    #[snafu(display("failed to read default config file {}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to deserialize default config file {}", path.display()))]
    Deserialize {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveDefaultConfigError {
    Serialize {
        path: PathBuf,
        source: toml::ser::Error,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl DefaultConfigFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            content: None,
            config: DefaultConfig::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(path: PathBuf) -> Result<Self, LoadDefaultConfigError> {
        let source = fs::read_to_string(&path)
            .await
            .context(load_default_config_error::IoSnafu { path: &path })?;
        let config: DefaultConfig = toml::from_str(&source)
            .context(load_default_config_error::DeserializeSnafu { path: &path })?;
        Ok(Self {
            path,
            content: Some(source),
            config,
        })
    }

    fn locate(&self, offset: usize) -> Option<FileLineCol> {
        let line_col = LineCol::locate(self.content.as_ref()?, offset);
        let path = self.path.clone();
        Some(FileLineCol { path, line_col })
    }

    pub fn config(&self) -> &DefaultConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut DefaultConfig {
        &mut self.config
    }

    pub async fn load_default_identity(
        &self,
        genmeta_home: &GenmetaHome,
    ) -> Option<Result<IdentityHome, LoadIdentityError>> {
        let name = self.config.name.as_ref()?;

        Some(
            genmeta_home
                .load_identity(name.as_ref().borrow())
                .await
                .context(load_identity_error::LoadIdentitySnafu {
                    config: self.locate(name.span().start),
                }),
        )
    }

    pub async fn save(&self) -> Result<(), SaveDefaultConfigError> {
        let source = toml::to_string_pretty(&self.config)
            .context(save_default_config_error::SerializeSnafu { path: &self.path })?;
        fs::write(&self.path, source)
            .await
            .context(save_default_config_error::IoSnafu { path: &self.path })?;
        Ok(())
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LoadDefaultIdentityError {
    #[snafu(transparent)]
    LoadDefaultConfig { source: LoadDefaultConfigError },
    #[snafu(display("no default identity configured"))]
    NoDefaultIdentity,
    #[snafu(transparent)]
    LoadIdentity { source: LoadIdentityError },
}

impl GenmetaHome {
    pub fn identity_default_config_path(&self) -> PathBuf {
        self.join(DefaultConfig::FILE_NAME)
    }

    pub async fn load_identity_default_config(
        &self,
    ) -> Result<DefaultConfigFile, LoadDefaultConfigError> {
        DefaultConfigFile::load(self.identity_default_config_path()).await
    }

    pub async fn load_default_identity(&self) -> Result<IdentityHome, LoadDefaultIdentityError> {
        Ok(self
            .load_identity_default_config()
            .await?
            .load_default_identity(self)
            .await
            .context(load_default_identity_error::NoDefaultIdentitySnafu)??)
    }

    pub fn new_identity_default_config(&self) -> DefaultConfigFile {
        DefaultConfigFile::new(self.identity_default_config_path())
    }
}
