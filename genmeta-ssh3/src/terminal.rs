use std::{io::Read, sync::Arc};

use bytes::Bytes;
use crossterm::terminal;
use futures::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    Error,
    mux::{Mux, OpenChannel, Recver, Sender},
};

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientTerminalMessage {
    WindowSize { rows: u16, cols: u16 },
    Sequence(Bytes),
}

pub type ServerTerminalMessage = Bytes;

#[derive(Debug, Default)]
pub struct Command {
    program: Option<String>,
    arguments: Option<Vec<String>>,
}

impl Command {
    pub async fn run(&self, mux: &Arc<Mux>, pseudo: bool) -> Result<(), Error> {
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

        tracing::debug!(target: "terminal", "Running command: {self:?} with Open {open:?}");
        let (_token, recver, sender) = mux
            .open::<ServerTerminalMessage, ClientTerminalMessage>(open)
            .await?;

        let _update_winize = AbortOnDropHandle::new(tokio::spawn(update_winsize(sender.clone())));
        let _send_terminal = AbortOnDropHandle::new(tokio::spawn(send_terminal(sender.clone())));

        // stdin 关闭不代表流关闭，以recv为准
        _ = recv_terminal(recver).await;

        Ok(())
    }
}

async fn update_winsize(mut message_sender: Sender<ClientTerminalMessage>) {
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
        tracing::error!(target: "terminal", "Failed to update terminal size: {e}");
    };

    use tokio::signal::unix::{SignalKind, signal};

    let mut signal_listener = match signal(SignalKind::window_change()) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(target: "terminal", "Failed to create signal handler for SIGWINCH: {e}");
            return;
        }
    };

    while let Some(()) = signal_listener.recv().await {
        if let Err(e) = update_winsize().await {
            tracing::error!(target: "terminal", "Failed to update terminal size: {e}");
        };
    }
}

async fn send_terminal(mut message_sender: Sender<ClientTerminalMessage>) {
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
            tracing::debug!(target: "terminal", "Read stdin EOF received");
            break;
        }

        let message = ClientTerminalMessage::Sequence(sequence);
        if message_sender.send(message).await.is_err() {
            tracing::error!(target: "terminal", "Event channel closed");
            return;
        }
    }
}

async fn recv_terminal(mut recver: Recver<ServerTerminalMessage>) {
    while let Ok(Some(sequence)) = recver.try_next().await {
        // 不知为何往tokio::stdin写时会缺少一行输出，所以使用stdio
        let write_to_stdout = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&sequence)?;
            stdout.flush()
        });
        if let Err(write_error) = write_to_stdout.await.expect("Write should never panic") {
            tracing::error!(target: "terminal", "Failed to write to stdout: {write_error}");
        }
    }
    tracing::debug!(target: "terminal", "recv_terminal: Recv EOF");
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
