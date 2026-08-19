pub(crate) mod apply;
pub(crate) mod auth_plan;
#[cfg(unix)]
pub(crate) mod auto_renew;
pub(crate) mod default_identity;
pub(crate) mod device;
pub(crate) mod email;
pub(crate) mod epilogue;
pub(crate) mod install;
pub(crate) mod key_material;
pub(crate) mod kind;
pub(crate) mod local;
pub(crate) mod output;
pub(crate) mod progress;
pub(crate) mod recovery;
pub(crate) mod registration;
pub(crate) mod renew;
pub(crate) mod site;
pub(crate) mod target;
pub(crate) mod transcript;
pub(crate) mod welcome;

use dhttp::home::{DhttpHome, HomeScope};

use crate::{
    cert_server::CertServer,
    cli::{Apply, Default, Error, Info, List, Renew, SiteCommand},
};

pub(crate) async fn run_apply(
    command: &Apply,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    apply::run(command, dhttp_home, home_scope, cert_server).await
}

pub(crate) async fn run_ensite(command: &SiteCommand, dhttp_home: &DhttpHome) -> Result<(), Error> {
    site::run_ensite(command, dhttp_home).await
}

pub(crate) async fn run_dissite(
    command: &SiteCommand,
    dhttp_home: &DhttpHome,
) -> Result<(), Error> {
    site::run_dissite(command, dhttp_home).await
}

pub(crate) async fn run_renew(
    command: &Renew,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    renew::run(command, dhttp_home, home_scope, cert_server).await
}

pub(crate) async fn run_default(
    command: &Default,
    dhttp_home: &DhttpHome,
    home_scope: HomeScope,
    cert_server: &CertServer,
) -> Result<(), Error> {
    default_identity::run(command, dhttp_home, home_scope, cert_server).await
}

pub(crate) async fn run_info(
    command: &Info,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    command.run(dhttp_home, cert_server).await
}

pub(crate) async fn run_list(
    command: &List,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    command.run(dhttp_home, cert_server).await
}
