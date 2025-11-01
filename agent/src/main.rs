mod commandline;

use std::io::{Write};
use anyhow::anyhow;
use events::{ProcessEventFields, ProcessEventPayload};
use one_collect::helpers::callstack::{CallstackHelp, CallstackHelper};

fn main() {
    do_etw();
}

fn do_etw() {
    let helper = CallstackHelper::new();
    let mut etw = one_collect::etw::EtwSession::new().with_callstack_help(&helper);
    let temp = std::env::temp_dir().join("agent_process_test.etl");
    let mut output_file = std::fs::OpenOptions::new().write(true).create(true).open(temp.clone()).unwrap();

    let event = etw.comm_start_event();
    let fields = ProcessEventFields::new(&event.format());
    event.add_callback(move |data| {
        let payload = ProcessEventPayload::from_event_data(data, &fields)
            .map_err(|e| anyhow!("Failed to create event payload: {:?}", e))?;

        output_file.write(payload.as_bytes().as_slice()).unwrap();

        Ok(())
    });

    let duration = std::time::Duration::from_secs(15);
    etw.parse_for_duration("agent_process_test", duration)
        .unwrap();
}
