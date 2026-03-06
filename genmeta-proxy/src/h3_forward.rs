use h3x::{gm_quic::H3Client, server::MessageStreamError};
use hyper::{
    Request, Response,
    body::{Body, Incoming},
};
use snafu::FromString;

use crate::Error;

/// Forward a plain HTTP request to a genmeta domain via DHTTP/3.
pub async fn forward_h3(
    req: Request<Incoming>,
    client: &H3Client,
) -> Result<Response<impl Body<Data = bytes::Bytes, Error = MessageStreamError>>, Error> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| {
            crate::Error::from(Box::new(genmeta_common::error::Whatever::without_source(
                "missing authority in DHTTP/3 request URI".to_string(),
            )))
        })?
        .clone();

    let connection = client.connect(authority.clone()).await.map_err(|e| {
        crate::Error::from(Box::new(genmeta_common::error::Whatever::with_source(
            Box::new(e),
            format!("failed to connect to DHTTP/3 server `{authority}`"),
        )))
    })?;

    let response = connection.execute_hyper_request(req).await.map_err(|e| {
        crate::Error::from(Box::new(genmeta_common::error::Whatever::with_source(
            Box::new(e),
            "failed to execute DHTTP/3 request".to_string(),
        )))
    })?;

    Ok(response)
}
