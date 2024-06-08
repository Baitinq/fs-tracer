use std::{collections::HashMap, sync::mpsc::Sender};

use fs_tracer_common::SyscallInfo;

pub struct SyscallHandler {
    resolved_files: Sender<String>,
    syscall_map: HashMap<u64, fn([u64; 6]) -> u64>, //TODO
}

impl SyscallHandler {
    pub fn new(resolved_files: Sender<String>) -> Self {
        Self {
            resolved_files,
            syscall_map: HashMap::new(),
        }
    }

    pub fn handle_syscall(&self, data: SyscallInfo) -> u64 {
        match data {
            SyscallInfo::Write(x) => {
                println!("WRITE KERNEL: DATA {:?}", x);
                let _ = self.resolved_files.send(format!(
                    r#"
                {{
                    "timestamp": "{}",
                    "absolute_path": "{}",
                    "contents": "{}"
                }}
                "#,
                    chrono::Utc::now().to_rfc3339(),
                    "/tmp/file.txt",
                    "some contents!!"
                ));
                return 0;
            }
            SyscallInfo::Open(x) => {
                // if !CStr::from_bytes_until_nul(&x.filename)
                //     .unwrap_or_default()
                //     .to_str()
                //     .unwrap_or_default()
                //     .starts_with('/')
                // {
                println!("OPEN KERNEL DATA: {:?}", x);
                return 0;
                // }
            }
        }
    }
}
