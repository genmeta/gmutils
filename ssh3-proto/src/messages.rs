use std::{fmt::Display, net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use derive_more::From;
use serde::{Deserialize, Serialize};

use crate::mux::Token;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    Open { token: Token, open: OpenChannel },
    Data { token: Token, data: Bytes },
    Error { token: Token, error: String },
    Close { token: Token },
    Headrbeat {},
}

#[derive(Debug, From, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum BindAddress {
    /// 包括IP地址
    Host { host: String, port: u16 },
    /// UNIX socket的路径
    Unix { path: PathBuf },
}

impl From<SocketAddr> for BindAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::Host {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }
}

impl Display for BindAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindAddress::Host { host, port } => write!(f, "{host}:{port}"),
            BindAddress::Unix { path } => Display::fmt(&path.display(), f),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OpenChannel {
    /// 打开认证通道
    ///
    /// 通道使用[`auth`]模块的消息
    Auth { username: String },
    /// 执行一个命令
    ///
    /// 通道使用[`session`]模块的消息
    Exec { pseudo: bool, command: String },
    /// 打开一个shell
    ///
    /// 通道使用[`session`]模块的消息
    Shell { pseudo: bool },
    /// 让对端监听一个地址，接收到的连接通过此管道请求转发
    ///
    /// 发起方关闭通道发送Close表示不希望Server继续监听
    ///
    /// 接收方关闭通道发送Error表示监听出错
    ///
    /// 当前客户端不接受此消息
    ///
    /// 通道不传输任何数据
    Forward {
        listen: BindAddress,
        /// 如果socks为false，Forwarded消息不携带to
        ///
        /// 如果socks为true，对端启动一个socks5代理服务器，Forwared携带代理连接期望连接到的地址
        socks: bool,
    },
    /// Forward的接受方从指定地址接收到连接，发送此消息请求转发
    ///
    /// 当前服务端不接受此消息
    ///
    /// 通道消息不序列化，使用streaming
    Forwarded {
        listen: Token,
        /// Forwarded接收方需要通过listen鉴权，listen应为对应Forward通道的token
        to: Option<BindAddress>,
    },
    /// 转发数据到对端的某地址
    ///
    /// 不同于Forwarded，这个是客户端发出的。客户端不接受此消息
    ///
    /// 通道消息不序列化，使用streaming
    Direct { to: BindAddress },
    // todo: Signal
}

pub mod auth {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ClientAuthMessage {
        Password(String),
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ServerAuthMessage {
        Accpet,
        Password { prompt: String },
        // Reject: Message::Error
    }
}

pub mod session {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ClientSessionMessage {
        WindowSize { rows: u16, cols: u16 },
        Sequence(Bytes),
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ServerSessionMessage {
        Sequence(Bytes),
        Exit { code: i32 },
    }
}
