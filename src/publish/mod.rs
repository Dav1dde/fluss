pub mod elastic;

pub use self::elastic::ElasticPublisher;

use crate::data::Record;

// TODO better name, actually get completely rid of this
pub trait Lookup {
    fn get_record_name(&self, record: &Record) -> Option<&str> {
        self.get_record_name_u16(record.id)
    }

    fn get_record_name_u16(&self, id: u16) -> Option<&str>;
}
