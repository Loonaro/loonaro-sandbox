mod commandline;

use one_collect::helpers::callstack::{CallstackHelp, CallstackHelper};

fn sid_length(data: &[u8]) -> anyhow::Result<usize> {
    const PTR_SIZE: usize = std::mem::size_of::<usize>();
    let mut sid_size: usize = PTR_SIZE;

    if data.len() < 8 {
        anyhow::bail!("Invalid SID length");
    }

    let sid = u64::from_ne_bytes(data[..8].try_into()?);

    if sid != 0 {
        let offset = PTR_SIZE * 2;
        let start = offset + 1;

        if data.len() < start {
            anyhow::bail!("Invalid SID length");
        }

        let auth_count = data[start..][0] as usize;
        sid_size = offset + 8 + (auth_count * 4);
    }

    Ok(sid_size)
}

fn main() {
    let helper = CallstackHelper::new();
    let mut etw = one_collect::etw::EtwSession::new().with_callstack_help(&helper);

    eprintln!(
        "{: <10} {: <10} {: <25} {: <25} {: <25}",
        "PID", "PPID", "User SID", "ImageFileName", "CommandLine"
    );

    etw.comm_start_event().add_callback(|data| {
        let fmt = data.format();
        let data = data.event_data();
        let pid = if let Some(v) = fmt.get_field_ref("ProcessId") {
            fmt.get_u32(v, data)?
        } else {
            eprintln!(">>>>> ProcessId not found");
            return Ok(());
        };

        let ppid = if let Some(v) = fmt.get_field_ref("ParentId") {
            fmt.get_u32(v, data)?
        } else {
            eprintln!(">>>>> ParentId not found");
            return Ok(());
        };

        let user_sid = if let Some(v) = fmt.get_field_ref("UserSID") {
            let data = fmt.get_data(v, data);
            let sid_len = sid_length(data)?;
            let sid = &data[..sid_len];
            format!("{:?}", sid)
        } else {
            eprintln!(">>>>> Invalid User SID");
            return Ok(());
        };

        let file_name_result = if let Some(v) = fmt.get_field_ref("ImageFileName") {
            fmt.get_str(v, data)
        } else {
            eprintln!(">>>>> ImageFileName not found");
            return Ok(());
        }?;

        let command_line = if let Some(v) = fmt.get_field_ref("CommandLine") {
            fmt.get_str(v, data)
        } else {
            eprintln!(">>>>> CommandLine not found");
            return Ok(());
        }?;

        let output = format!(
            "{: <10} {: <10} {: <25} {:<25} {:<25}",
            pid, ppid, user_sid, file_name_result, command_line
        );
        println!("{}", output);
        Ok(())
    });

    let duration = std::time::Duration::from_secs(15);
    etw.parse_for_duration("agent_process_test", duration)
        .unwrap();
}
