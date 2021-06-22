use super::Publisher;
use crate::fluss::Fluss;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use elasticsearch::{Elasticsearch, IndexParts};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Document<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: DateTime<Utc>,

    #[serde(flatten)]
    fluss: &'a Fluss,
}

impl<'a> Document<'a> {
    fn new(fluss: &'a Fluss) -> Self {
        Self {
            timestamp: fluss.time_received,
            fluss,
        }
    }
}

pub struct ElasticPublisher {
    client: Elasticsearch,
    index: String,
}

impl ElasticPublisher {
    pub fn new(client: Elasticsearch) -> Self {
        Self {
            client,
            index: "fluss".to_string(),
        }
    }

    pub fn set_index(&mut self, index: impl Into<String>) {
        self.index = index.into();
    }

    fn current_index(&self) -> String {
        format!("{}-{}", self.index, Utc::today().format("%d.%m.%Y"))
    }
}

#[async_trait]
impl Publisher for ElasticPublisher {
    async fn publish(&self, fluss: &Fluss) -> anyhow::Result<()> {
        // TODO bulk inserts with in memory batches, probably through a channel
        // and multiple workers

        self.client
            .index(IndexParts::Index(&self.current_index()))
            .body(Document::new(fluss))
            .send()
            .await?;

        Ok(())
    }
}
