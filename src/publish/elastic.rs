use crate::fluss::Fluss;
use elasticsearch::{Elasticsearch, IndexParts};

pub struct ElasticPublisher {
    client: Elasticsearch,
}

impl ElasticPublisher {
    pub fn new(client: Elasticsearch) -> Self {
        Self { client }
    }

    pub async fn publish(&self, fluss: &Fluss) -> anyhow::Result<()> {
        // TODO bulk inserts with in memory batches, probably through a channel
        // and multiple workers

        self.client
            .index(IndexParts::Index("fluss-2"))
            .body(fluss)
            .send()
            .await?;

        Ok(())
    }
}
