use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Request, Response, body::Incoming, upgrade::on as upgrade_on};
use hyper_util::rt::TokioIo;
use snafu::ResultExt;
use tokio::{io::copy_bidirectional, net::TcpStream};

use crate::Error;

/// Handle an HTTP CONNECT tunnel request by upgrading the connection and
/// proxying data between the client and the target TCP address.
pub async fn tunnel_connect(
    req: Request<Incoming>,
    addr: &str,
) -> Result<Response<Empty<Bytes>>, Error> {
    // Capture the upgrade future BEFORE returning the 200 response
    let upgrade_fut = upgrade_on(req);
    let addr = addr.to_owned();

    tokio::spawn(async move {
        match upgrade_fut.await.context(crate::TunnelUpgradeSnafu) {
            Err(e) => {
                tracing::error!(error = %e, "Failed to upgrade tunnel connection");
            }
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                match TcpStream::connect(&addr)
                    .await
                    .context(crate::TunnelConnectSnafu { addr: &addr })
                {
                    Err(e) => {
                        tracing::error!(error = %e, addr = %addr, "Failed to connect to tunnel target");
                    }
                    Ok(mut stream) => {
                        // TcpStream implements tokio AsyncRead/AsyncWrite directly
                        if let Err(e) = copy_bidirectional(&mut client_io, &mut stream).await {
                            tracing::error!(error = %e, addr = %addr, "Tunnel copy error");
                        }
                    }
                }
            }
        }
    });

    Ok(Response::builder().status(200).body(Empty::new()).unwrap())
}
