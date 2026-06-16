pub(crate) mod apply;
pub(crate) mod approval;
pub(crate) mod create;
pub(crate) mod default_identity;
pub(crate) mod device;
pub(crate) mod email;
pub(crate) mod epilogue;
pub(crate) mod kind;
pub(crate) mod local;
pub(crate) mod output;
pub(crate) mod progress;
pub(crate) mod recovery;
pub(crate) mod renew;
pub(crate) mod target;
pub(crate) mod transcript;

use dhttp::home::DhttpHome;

use crate::{
    cert_server::CertServer,
    cli::{Apply, Create, Default, Error, Info, List, Renew},
};

pub(crate) async fn run_create(
    command: &Create,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    create::run(command, dhttp_home, cert_server).await
}

pub(crate) async fn run_apply(
    command: &Apply,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    apply::run(command, dhttp_home, cert_server).await
}

pub(crate) async fn run_renew(
    command: &Renew,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    renew::run(command, dhttp_home, cert_server).await
}

pub(crate) async fn run_default(
    command: &Default,
    dhttp_home: &DhttpHome,
    cert_server: &CertServer,
) -> Result<(), Error> {
    default_identity::run(command, dhttp_home, cert_server).await
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
