use h3x::{dquic::H3Client, server::MessageStreamError};
use hyper::{
    Request, Response,
    body::{Body, Incoming},
};
use snafu::ResultExt;

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
            <Error as snafu::FromString>::without_source(
                "missing authority in DHTTP/3 request URI".to_string(),
            )
        })?
        .clone();

    let connection = client
        .connect(authority.clone())
        .await
        .whatever_context::<_, Error>(format!(
            "failed to connect to DHTTP/3 server `{authority}`"
        ))?;

    let response = connection
        .execute_hyper_request(req)
        .await
        .whatever_context::<_, Error>("failed to execute DHTTP/3 request")?;
    Ok(response)
}
