mod sdk;

use sdk::{Request, Response};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Message {
    message: String,
}

fn hello(_request: Request) -> sdk::Result {
    Response::json(Message {
        message: "Hello from Rust".into(),
    })
}

fn echo(request: Request) -> sdk::Result {
    let input: Message = request.json()?;
    Response::json(input)
}

sdk::api! {
    get "/hello" => hello,
    post "/echo" => echo,
}
