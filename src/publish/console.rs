use super::Publisher;
use crate::fluss::Fluss;
use async_trait::async_trait;

pub struct ConsolePublisher {}

impl ConsolePublisher {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Publisher for ConsolePublisher {
    async fn publish(&self, fluss: &Fluss) -> anyhow::Result<()> {
        tracing::info!("{:?}", fluss);
        Ok(())
    }
}

impl Default for ConsolePublisher {
    fn default() -> Self {
        Self::new()
    }
}
