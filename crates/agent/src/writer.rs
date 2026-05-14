//! A serialized stdout writer. Handlers send Messages through an mpsc; one
//! background task is the sole writer to stdout. Keeps the wire stream coherent
//! even when multiple handlers want to emit progress concurrently.

use rsansible_wire::{write_frame, Message};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::error;

/// Channel capacity. Generous — TaskProgress chunks shouldn't queue much in
/// practice (writer drains as fast as SSH can ship), but a big buffer absorbs
/// burst output without backpressuring command stdout pipes into stalling.
const WRITER_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct Sender(pub mpsc::Sender<Message>);

impl Sender {
    pub async fn send(&self, m: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.0.send(m).await
    }
}

pub fn spawn<W>(out: W) -> (Sender, JoinHandle<()>)
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Message>(WRITER_CAPACITY);
    let handle = tokio::spawn(async move {
        let mut out = out;
        while let Some(m) = rx.recv().await {
            if let Err(e) = write_frame(&mut out, &m).await {
                // We can't ship the error back over the wire we just failed to
                // write to. Log on stderr and stop — the loop in main will
                // observe the dropped receiver via its next send.
                error!(error = %e, "stdout write failed; writer task exiting");
                return;
            }
            // `tokio::io::stdout()` wraps a `BufWriter` internally; without an
            // explicit flush after each frame, encoded bytes sit in the buffer
            // and the controller never sees them until the buffer fills (or
            // the process exits). Subtle deadlock when run under a parent
            // process expecting a frame-by-frame stream.
            if let Err(e) = out.flush().await {
                error!(error = %e, "stdout flush failed; writer task exiting");
                return;
            }
        }
        // Channel closed; flush before exit so the controller sees our final
        // frame (typically a TaskDone right before the agent's main loop
        // observes Bye and tears down).
        if let Err(e) = out.flush().await {
            error!(error = %e, "stdout flush failed at writer shutdown");
        }
    });
    (Sender(tx), handle)
}
