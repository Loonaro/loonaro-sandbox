use minicbor::Decode;
use minicbor::Encode;
use serde::{Deserialize, Serialize};

pub enum EtwEvent {
    System(EtwEvent)
}

pub enum System {
    ProcessCreate,
    ProcessTerminate,
}

#[derive(Serialize, Deserialize)]
struct TLV {

}
