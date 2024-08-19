use libc::O_APPEND;
use log::info;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::{ffi::CStr, fs::File};

use crossbeam_channel::Sender;
use delay_map::HashMapDelay;

use fs_tracer_common::{
    CloseSyscallBPF, FSeekSyscallBPF, OpenSyscallBPF, SyscallInfo, WriteSyscallBPF,
};

use crate::FSTracerFile;

#[derive(Clone, Debug)]
struct OpenFile {
    filename: String,
    offset: i64,
    contents: String,
    has_append_mode: bool,
}

pub struct SyscallHandler {
    resolved_files: Sender<FSTracerFile>,
    open_files: HashMapDelay<(i32, u32), OpenFile>,
    seen_files: HashMap<String, String>,
}

impl SyscallHandler {
    pub fn new(resolved_files: Sender<FSTracerFile>) -> Self {
        Self {
            resolved_files,
            open_files: HashMapDelay::new(std::time::Duration::from_secs(400)),
            seen_files: HashMap::new(),
        }
    }

    pub fn handle_syscall(&mut self, data: SyscallInfo) -> Result<(), ()> {
        match data {
            SyscallInfo::Write(write_syscall) => self.handle_write(write_syscall),
            SyscallInfo::Open(open_syscall) => self.handle_open(open_syscall),
            SyscallInfo::FSeek(fseek_syscall) => self.handle_fseek(fseek_syscall),
            SyscallInfo::Close(close_syscall) => self.handle_close(close_syscall),
        }
    }

    fn handle_write(&mut self, write_syscall: WriteSyscallBPF) -> Result<(), ()> {
        let mut open_file = match self.open_files.get(&(write_syscall.fd, write_syscall.pid)) {
            None => {
                info!(
                    "DIDNT FIND AN OPEN FILE FOR THE WRITE SYSCALL (fd: {}, ret: {})",
                    write_syscall.fd, write_syscall.ret
                );
                return Ok(());
            }
            Some(str) => str.clone(),
        };
        let buf = CStr::from_bytes_until_nul(&write_syscall.buf)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();

        if open_file.has_append_mode {
            open_file.offset = open_file.contents.len() as i64;
        }

        let mut new_contents = open_file.contents.clone();
        let buf_size = buf.len();
        let start = open_file.offset as usize;
        let end = start + buf_size;
        if end > new_contents.len() {
            new_contents.push_str(&"*".repeat(end as usize - new_contents.len()));
        }
        new_contents.replace_range(start..end, buf);

        info!(
            "WRITE KERNEL: DATA {:?} FILENAME: {:?} STORED OFFSET: {:?} LEN: {:?} OLD_CONTENTS: {:?}, NEW_CONTENTS: {:?}",
            write_syscall,
            open_file.filename,
            open_file.offset,
            buf.len(),
            open_file.contents,
            new_contents
        );
        self.resolved_files
            .send(FSTracerFile {
                timestamp: chrono::Utc::now().to_rfc3339(),
                absolute_path: open_file.filename.to_string(),
                contents: new_contents.clone(),
            })
            .expect("Failed to send file to the resolved_files channel!");
        self.open_files
            .remove(&(write_syscall.fd, write_syscall.pid));
        self.open_files.insert(
            (write_syscall.fd, write_syscall.pid),
            OpenFile {
                filename: open_file.filename,
                offset: open_file.offset + write_syscall.count,
                contents: new_contents,
                has_append_mode: open_file.has_append_mode,
            },
        );
        Ok(())
    }

    fn handle_fseek(&mut self, fseek_syscall: FSeekSyscallBPF) -> Result<(), ()> {
        let open_file = match self.open_files.get(&(fseek_syscall.fd, fseek_syscall.pid)) {
            None => {
                info!(
                    "DIDNT FIND AN OPEN FILE FOR THE FSEEK SYSCALL (fd: {}, ret: {})",
                    fseek_syscall.fd, fseek_syscall.ret
                );
                return Ok(());
            }
            Some(str) => str.clone(),
        };
        info!(
            "FSEEK KERNEL: DATA {:?} FILENAME: {:?} STORED OFFSET: {:?}",
            fseek_syscall, open_file.filename, open_file.offset,
        );
        self.open_files
            .remove(&(fseek_syscall.fd, fseek_syscall.pid));

        let final_offset: i64 = match fseek_syscall.whence {
            0 => fseek_syscall.offset,                    //SEEK_SET
            1 => open_file.offset + fseek_syscall.offset, //SEEK_CUR
            2 => -1,                                      //SEEK_END
            _ => panic!("Invalid whence value!"),
        };

        self.open_files.insert(
            (fseek_syscall.fd, fseek_syscall.pid),
            OpenFile {
                filename: open_file.filename,
                offset: final_offset,
                contents: open_file.contents,
                has_append_mode: open_file.has_append_mode,
            },
        );
        Ok(())
    }

    fn handle_open(&mut self, open_syscall: OpenSyscallBPF) -> Result<(), ()> {
        let filename = CStr::from_bytes_until_nul(&open_syscall.filename)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        info!("OPEN KERNEL DATA: {:?}", open_syscall);
        info!("OPEN FILENAME: {:?}", filename);

        // if filename.starts_with("/") && !filename.starts_with("/home/") {
        //     info!("Ignoring file: {}", filename);
        //     return Ok(());
        // }
        //
        // let mut contents = "".to_string();
        // let path = Path::new(filename);
        // if false && path.exists() && !path.is_dir() {
        //     info!("Will read file contents for {}", filename);
        //     let mut buf = vec![];
        //     let mut file = File::open(filename).expect("unable to open file for reading");
        //     file.read_to_end(&mut buf).expect("unable to read file");
        //     let str = String::from_utf8_lossy(&buf);
        //     contents = str.to_string();
        //     info!("Read file contents for {}", filename);
        // } else {
        //     info!("File previously didnt exist: {}", filename);
        // }
        //

        let mut contents = String::from("");
        match self.seen_files.get(filename) {
            Some(content) => {
                contents = content.to_string();
                info!(
                    "Fetched file contents from memory {}: {}",
                    filename, content
                );
            }
            None => {
                info!("File previously wasnt seen: {}", filename);
            }
        }

        let fd = open_syscall.ret;
        let has_append_mode = open_syscall.flags == O_APPEND;
        self.open_files.insert(
            (fd, open_syscall.pid),
            OpenFile {
                filename: filename.to_string(),
                offset: 0,
                contents,
                has_append_mode,
            },
        );
        Ok(())
    }

    fn handle_close(&mut self, close_syscall: CloseSyscallBPF) -> Result<(), ()> {
        let open_file = match self
            .open_files
            .remove(&(close_syscall.fd, close_syscall.pid))
        {
            None => {
                info!(
                    "DIDNT FIND AN OPEN FILE FOR THE CLOSE SYSCALL (fd: {})",
                    close_syscall.fd
                );
                return Ok(());
            }
            Some(str) => str,
        };
        info!("CLOSE KERNEL DATA: {:?}", close_syscall);
        info!(
            "CLOSE FILENAME {:?} with contents: {:?}",
            open_file.filename, open_file.contents
        );

        // NOTE: This is a hack.
        self.seen_files
            .insert(open_file.filename, open_file.contents);

        Ok(())
    }
}
