use super::Lookup;
use crate::data::RecordSet;
use elasticsearch::{Elasticsearch, IndexParts};
use std::collections::HashMap;

pub struct ElasticPublisher {
    client: Elasticsearch,
}

impl ElasticPublisher {
    pub fn new(client: Elasticsearch) -> Self {
        Self { client }
    }

    pub async fn publish(
        &self,
        record: &RecordSet<'_>,
        lookup: &impl Lookup,
    ) -> anyhow::Result<()> {
        // TODO bulk inserts with in memory batches, probably through a channel
        // and multiple workers

        let mut records = record
            .records
            .iter()
            .filter_map(|r| lookup.get_record_name(&r).map(|name| (name, &r.value)))
            .collect::<HashMap<_, _>>();

        let t = crate::data::Value::String(chrono::Utc::now().to_rfc3339());
        records.insert("@timestamp", &t);

        self.client
            .index(IndexParts::Index("fluss"))
            .body(records)
            .send()
            .await?;

        Ok(())
    }
}
