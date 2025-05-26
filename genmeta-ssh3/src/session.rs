use std::{io::Read, sync::Arc};

use bytes::Bytes;
use crossterm::terminal;
use futures::{Sink, SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use ssh3_proto::{
    messages::{OpenChannel, session::ServerSessionMessage},
    mux::FramedRecver,
};
use tokio_util::task::AbortOnDropHandle;

use crate::{Error, mux::Mux};

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientTerminalMessage {
    WindowSize { rows: u16, cols: u16 },
    Sequence(Bytes),
}

#[derive(Debug, Default)]
pub struct Command {
    program: Option<String>,
    arguments: Option<Vec<String>>,
}

impl Command {
    pub async fn run(&self, mux: &Arc<Mux>, pseudo: bool) -> Result<i32, Error> {
        let open = match &self.program {
            Some(program) => {
                if let Some(arguments) = &self.arguments {
                    OpenChannel::Exec {
                        pseudo,
                        command: [program, arguments.join(" ").as_str()].join(" "),
                    }
                } else {
                    OpenChannel::Exec {
                        pseudo,
                        command: program.to_string(),
                    }
                }
            }
            None => OpenChannel::Shell { pseudo },
        };

        tracing::debug!(target: "session", "Running command: {self:?} with Open {open:?}");
        let (_token, recver, sender) = mux.open(open).await?;

        let _update_winize =
            AbortOnDropHandle::new(tokio::spawn(update_winsize(sender.clone().framed())));
        let _send_terminal =
            AbortOnDropHandle::new(tokio::spawn(send_terminal(sender.clone().framed())));

        // stdin 关闭不代表流关闭，以recv为准
        recv_terminal(recver.framed()).await
    }
}

async fn update_winsize(mut message_sender: impl Sink<ClientTerminalMessage> + Unpin) {
    let mut update_winsize = async || {
        let message = match terminal::size() {
            Ok((cols, rows)) => ClientTerminalMessage::WindowSize { rows, cols },
            Err(e) => {
                return Err(Error::from(format!("Failed to get terminal size: {e}")));
            }
        };
        if message_sender.send(message).await.is_err() {
            return Err("Event channel closed".into());
        }
        Ok(())
    };

    if let Err(e) = update_winsize().await {
        tracing::error!(target: "session", "Failed to update terminal size: {e}");
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut signal_listener = match signal(SignalKind::window_change()) {
            Ok(listener) => listener,
            Err(e) => {
                tracing::error!(target: "session", "Failed to create signal handler for SIGWINCH: {e}");
                return;
            }
        };

        while let Some(()) = signal_listener.recv().await {
            if let Err(e) = update_winsize().await {
                tracing::error!(target: "session", "Failed to update terminal size: {e}");
            };
        }
    }

    #[cfg(not(unix))]
    compile_error!("Unsupported platform for terminal size updates");
}

async fn send_terminal(mut message_sender: impl Sink<ClientTerminalMessage> + Unpin) {
    // tokio::io::stdin() 不适合交互使用，读文档了解详情
    let tracing_span = tracing::Span::current();
    let (sequence_tx, mut sequence_rx) = tokio::sync::mpsc::channel::<Bytes>(32);
    std::thread::spawn(move || {
        let _entered = tracing_span.entered();
        loop {
            let mut buf = [0; 4096];
            match std::io::stdin().read(&mut buf) {
                Ok(nread) => {
                    if sequence_tx
                        .blocking_send(buf[..nread].to_vec().into())
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!(target:"ssh", "Failed to read from stdin: {e}");
                    break;
                }
            }
        }
    });

    while let Some(sequence) = sequence_rx.recv().await {
        // read() -> Ok(0)
        if sequence.is_empty() {
            tracing::debug!(target: "session", "Read stdin EOF received");
            break;
        }

        let message = ClientTerminalMessage::Sequence(sequence);
        if message_sender.send(message).await.is_err() {
            tracing::error!(target: "session", "Event channel closed");
            return;
        }
    }
}

async fn recv_terminal(mut recver: FramedRecver<ServerSessionMessage>) -> Result<i32, Error> {
    while let Some(message) = recver.try_next().await? {
        match message {
            ServerSessionMessage::Sequence(sequence) => {
                // 不知为何往tokio::stdin写时会缺少一行输出，所以使用stdio
                let write_to_stdout = tokio::task::spawn_blocking(move || {
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&sequence)?;
                    stdout.flush()
                });
                if let Err(write_error) = write_to_stdout.await.expect("Write should never panic") {
                    tracing::error!(target: "session", "Failed to write to stdout: {write_error}");
                }
            }
            ServerSessionMessage::Exit { code } => return Ok(code),
        }
    }
    tracing::debug!(target: "session", "recv_terminal: Recv EOF");
    Err("Server closed unexpected".into())
}

impl super::Options {
    pub fn command(&self) -> Command {
        match self.commands.as_slice() {
            [] => Command::default(),
            [command] => Command {
                program: Some(command.to_string()),
                arguments: None,
            },
            [command, arguments @ ..] => Command {
                program: Some(command.to_string()),
                arguments: Some(arguments.to_vec()),
            },
        }
    }
}
