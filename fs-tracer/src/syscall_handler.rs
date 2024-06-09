use std::{collections::HashMap, ffi::CStr, sync::mpsc::Sender};

use fs_tracer_common::SyscallInfo;

pub struct SyscallHandler {
    resolved_files: Sender<String>,
    open_files: HashMap<i32, String>,
}

impl SyscallHandler {
    pub fn new(resolved_files: Sender<String>) -> Self {
        Self {
            resolved_files,
            open_files: HashMap::new(),
        }
    }

    pub fn handle_syscall(&mut self, data: SyscallInfo) -> u64 {
        match data {
            SyscallInfo::Write(x) => {
                let filename = self.open_files.get(&x.fd);
                let filename = match filename {
                    None => {
                        println!("DIDNT FIND AN OPEN FILE FOR THE WRITE SYSCALL");
                        return 0;
                    }
                    Some(x) => x,
                };
                let contents = CStr::from_bytes_until_nul(&x.buf)
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default();
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
                    filename,
                    contents,
                ));
                return 0;
            }
            SyscallInfo::Open(x) => {
                let filename = CStr::from_bytes_until_nul(&x.filename)
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default();
                println!("OPEN KERNEL DATA: {:?}", x);
                println!("OPEN FILENAME: {:?}", filename);
                self.open_files.insert(x.ret, filename.to_string());
                return 0;
            } //SyscallInfo::Close
        }
    }
}
