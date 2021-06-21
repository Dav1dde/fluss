pub mod console;
pub mod elastic;

pub use self::console::ConsolePublisher;
pub use self::elastic::ElasticPublisher;

use crate::fluss::Fluss;
use async_trait::async_trait;

#[async_trait]
pub trait Publisher {
    async fn publish(&self, fluss: &Fluss) -> anyhow::Result<()>;
}
