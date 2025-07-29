use std::{
    backtrace::Backtrace,
    fmt::Debug,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::SeqCst},
    },
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use dashmap::{DashMap, Entry};
use derive_more::Display;
use futures::{Sink, SinkExt, Stream, StreamExt, channel::mpsc};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu, ensure};
use tokio::{io, time};
use tokio_util::{
    codec,
    io::{CopyToBytes, SinkWriter, StreamReader},
};
use tracing::Instrument;

use crate::{
    cbor_codec,
    messages::{Message, OpenChannel},
};

#[derive(Debug, Display, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Token(u64);

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Server,
}

impl Token {
    pub fn new(role: Role, seq: u64) -> Self {
        let mut token = seq << 1;
        match role {
            Role::Client => token |= 0b01,
            Role::Server => token |= 0b00,
        }
        Token(token)
    }

    pub fn seq(&self) -> u64 {
        self.0 >> 1
    }

    pub fn role(&self) -> Role {
        if self.0 & 0b01 == 0 {
            Role::Server
        } else {
            Role::Client
        }
    }

    pub fn into_inner(self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Self {
        Token(self.0 + 2)
    }
}

pub struct Mux {
    token_gen: AtomicU64,
    channels: DashMap<Token, mpsc::Sender<io::Result<Bytes>>>,
    message_sender: mpsc::Sender<Message>,
}

impl Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux")
            .field("token_gen", &self.token_gen)
            .field("channels", &self.channels)
            .field("message_sender", &"...")
            .finish()
    }
}

#[derive(Debug, Snafu)]
pub enum ChannelError {
    #[snafu(display("Peer has the same role with local when routing for {token}"))]
    SameRole { token: Token, backtrace: Backtrace },
    #[snafu(display("Channel {token} already be opened"))]
    ChannelAlreadyOpen { token: Token, backtrace: Backtrace },
    #[snafu(display("Channel {token} already be closed"))]
    ChannelClosed { token: Token, backtrace: Backtrace },
    #[snafu(display("Failed to send open message for {token}"))]
    SendOpen { token: Token, backtrace: Backtrace },
    #[snafu(display("Failed to send close message for {token}"))]
    SendClose { token: Token, backtrace: Backtrace },
}

#[derive(Debug, Snafu)]
pub enum ForwardError<Oe: snafu::Error + 'static> {
    #[snafu(display("Accept channel failed: {source}"))]
    AcceptChannel {
        source: ChannelError,
        backtrace: Backtrace,
    },
    #[snafu(display("Message stream closed: {source}"))]
    StreamClosed { source: Oe, backtrace: Backtrace },
}

pub type Incomings<StE = io::Error> = mpsc::Receiver<Result<NewChannel, ForwardError<StE>>>;

impl Mux {
    pub fn new<St, StE, Si>(role: Role, mut stream: St, mut sink: Si) -> (Arc<Self>, Incomings<StE>)
    where
        St: Stream<Item = Result<Message, StE>> + Send + Unpin + 'static,
        StE: snafu::Error + Send,
        Si: Sink<Message, Error: Debug> + Send + Unpin + 'static,
    {
        let (message_sender, mut pending_messages) = mpsc::channel::<Message>(8);
        let mut headrbeat_sender = message_sender.clone();
        let (mut incoming_forwarder, incomings) = mpsc::channel(8);

        let this = Arc::new(Mux {
            token_gen: AtomicU64::new(Token::new(role, 0).into_inner()),
            channels: DashMap::new(),
            message_sender,
        });

        let mux = this.clone();
        let task = async move {
            let recv_messages = async {
                while let Some(item) = stream.next().await {
                    let new_channel = match item {
                        Ok(item) => mux.receive(item).await.context(AcceptChannelSnafu),
                        Err(error) => Err(error).context(StreamClosedSnafu),
                    };

                    let is_err = new_channel.is_err();
                    if let Some(new_channel) = new_channel.transpose() {
                        _ = incoming_forwarder.send(new_channel).await;
                    }
                    if is_err {
                        break;
                    }
                }
                tracing::debug!(target: "mux", "Incoming stream closed");
                std::future::pending().await // hold the incoming_forwarder
            };
            let send_messages = async {
                while let Some(message) = pending_messages.next().await {
                    tracing::trace!(target: "mux", ?message, "Send message");
                    if let Err(error) = sink.send(message).await {
                        tracing::warn!(target: "mux", ?error, "Failed to send message");
                        return;
                    }
                }
            };
            let headrbeat = async move {
                let mut interval = time::interval(time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    _ = headrbeat_sender.send(Message::Headrbeat {}).await
                }
            };
            tokio::select! {
                _ = recv_messages => {},
                _ = send_messages => {},
                _ = headrbeat => {},
            }
            _ = sink.close().await;
            tracing::debug!(target: "mux", "Sink closed");
        };

        tokio::spawn(task.in_current_span());
        (this, incomings)
    }

    fn token(&self) -> Token {
        Token(self.token_gen.load(SeqCst))
    }

    fn next_token(&self) -> Token {
        let token = self.token_gen.fetch_add(2, SeqCst);
        Token(token)
    }

    async fn receive(
        self: &Arc<Self>,
        message: Message,
    ) -> Result<Option<NewChannel>, ChannelError> {
        tracing::trace!(target: "mux", ?message, "Received message");
        match message {
            Message::Open {
                token,
                open: request,
            } => {
                ensure!(token.role() != self.token().role(), SameRoleSnafu { token });
                let (sender, recver) = mpsc::channel(8);
                let entry = self.channels.entry(token);
                if let Entry::Occupied(..) = &entry {
                    return ChannelAlreadyOpenSnafu { token }.fail();
                }
                entry.insert(sender);

                let recver = Recver {
                    token,
                    mux: self.clone(),
                    stream: recver,
                };
                let sender = Sender {
                    token,
                    mux: self.clone(),
                    sink: self.message_sender.clone(),
                };

                let channel = NewChannel {
                    token,
                    sender,
                    recver,
                    request,
                };
                Ok(Some(channel))
            }
            Message::Data { token, data } => {
                let channel = self.channels.entry(token);
                if let Entry::Occupied(mut channel) = channel
                    && channel.get_mut().send(Ok(data)).await.is_err()
                {
                    channel.remove();
                }
                Ok(None)
            }
            Message::Error { token, error } => {
                let channel = self.channels.entry(token);
                let item = Err(io::Error::new(io::ErrorKind::BrokenPipe, error));
                // kept channel is successfully sent
                if let Entry::Occupied(mut channel) = channel
                    && let Err(error) = channel.get_mut().send(item).await
                {
                    tracing::warn!(target: "mux", ?token, "Failed to forward error message to channel: {error:?}");
                }
                Ok(None)
            }
            Message::Close { token } => {
                if let Some(mut channel) = self.channels.get(&token).map(|entry| entry.clone()) {
                    tracing::debug!(target: "mux", ?token, "Channel closed by peer");
                    if let Err(error) = channel.close().await {
                        tracing::warn!(target: "mux", ?token, "Failed to close channel: {error:?}");
                    }
                }
                Ok(None)
            }
            Message::Headrbeat {} => {
                tracing::debug!(target: "mux", "Received heartbeat");
                Ok(None)
            }
        }
    }

    pub async fn open(
        self: &Arc<Self>,
        open: OpenChannel,
    ) -> Result<(Token, Recver, Sender), ChannelError> {
        let token = self.next_token();
        let mut message_sender = self.message_sender.clone();
        let (sender, recver) = mpsc::channel(8);

        let entry = self.channels.entry(token);
        ensure!(
            matches!(entry, Entry::Vacant(..)),
            ChannelAlreadyOpenSnafu { token }
        );
        entry.insert(sender);

        let open = Message::Open { token, open };

        if message_sender.send(open).await.is_err() {
            // unknown reason
            return SendOpenSnafu { token }.fail();
        };

        let recver = Recver {
            token,
            mux: self.clone(),
            stream: recver,
        };
        let sender = Sender {
            token,
            mux: self.clone(),
            sink: message_sender,
        };
        Ok((token, recver, sender))
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        self.channels.clear();
    }
}

#[derive(Debug)]
pub struct NewChannel {
    pub token: Token,
    pub request: OpenChannel,
    pub sender: Sender,
    pub recver: Recver,
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct Recver {
        token: Token,
        mux: Arc<Mux>,
        #[pin]
        stream: mpsc::Receiver<io::Result<Bytes>>,
    }

    impl PinnedDrop for Recver {
        fn drop(this: Pin<&mut Self>) {
            let project = this.project();
            project.mux.channels.remove(project.token);
        }
    }
}

pub type StreamingRecver = StreamReader<Recver, Bytes>;
pub type FramedRecver<T> = codec::FramedRead<StreamingRecver, cbor_codec::CborDecoder<'static, T>>;

impl Recver {
    pub fn streaming(self) -> StreamReader<Self, Bytes> {
        StreamReader::new(self)
    }

    pub fn framed<T: Deserialize<'static>>(self) -> FramedRecver<T> {
        codec::FramedRead::new(self.streaming(), cbor_codec::CborDecoder::default())
    }
}

impl Stream for Recver {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug, Clone)]
    pub struct Sender {
        token: Token,
        mux: Arc<Mux>,
        #[pin]
        sink: mpsc::Sender<Message>,
    }
}

pub type StreamingSender = SinkWriter<CopyToBytes<Sender>>;
// pub type FramedSender<T> =

impl Sender {
    pub async fn cancel(&mut self, error: impl ToString) -> Result<(), ChannelError> {
        self.sink
            .send(Message::Error {
                token: self.token,
                error: error.to_string(),
            })
            .await
            .map_err(|_se| SendCloseSnafu { token: self.token }.build())
    }

    pub fn streaming(self) -> SinkWriter<CopyToBytes<Self>> {
        SinkWriter::new(CopyToBytes::new(self))
    }

    pub fn framed<T: Serialize>(self) -> FramedSender<T> {
        FramedSender {
            sender: self,
            _t: PhantomData,
        }
    }
}

impl Sink<Bytes> for Sender {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .sink
            .poll_ready(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        project
            .sink
            .start_send(Message::Data {
                token: *project.token,
                data: item,
            })
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        project
            .sink
            .poll_flush(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.project();
        ready!(
            (project.sink.as_mut().poll_ready(cx)).map_err(|se| io::Error::other(format!(
                "Mux sender failed to ready for Close: {se:?}"
            )))?
        );
        Poll::Ready(
            project
                .sink
                .start_send(Message::Close {
                    token: *project.token,
                })
                .map_err(|_se| io::ErrorKind::BrokenPipe.into()),
        )
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct FramedSender<T> {
        #[pin]
        sender: Sender,
        _t: PhantomData<T>
    }
}

impl<T> FramedSender<T> {
    pub async fn cancel(&mut self, error: io::Error) -> Result<(), ChannelError> {
        self.sender.cancel(error).await
    }
}

impl<T> Clone for FramedSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            _t: PhantomData,
        }
    }
}

impl<T: Serialize> Sink<T> for FramedSender<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sender.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.project().sender.start_send(
            serde_cbor::to_vec(&item)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to serialize: {e}"),
                    )
                })?
                .into(),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sender.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sender.poll_close(cx)
    }
}
