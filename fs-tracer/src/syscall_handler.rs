use std::ffi::CStr;

use crossbeam_channel::Sender;
use delay_map::HashMapDelay;

use fs_tracer_common::{
    CloseSyscallBPF, FSeekSyscallBPF, OpenSyscallBPF, SyscallInfo, WriteSyscallBPF,
};

use crate::FSTracerFile;

pub struct SyscallHandler {
    resolved_files: Sender<FSTracerFile>,
    open_files: HashMapDelay<(i32, u32), (String, i64)>,
}

impl SyscallHandler {
    pub fn new(resolved_files: Sender<FSTracerFile>) -> Self {
        Self {
            resolved_files,
            open_files: HashMapDelay::new(std::time::Duration::from_secs(400)),
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
        let (filename, offset) = match self.open_files.get(&(write_syscall.fd, write_syscall.pid)) {
            None => {
                println!(
                    "DIDNT FIND AN OPEN FILE FOR THE WRITE SYSCALL (fd: {}, ret: {})",
                    write_syscall.fd, write_syscall.ret
                );
                return Ok(());
            }
            Some(str) => str.clone(),
        };
        let contents = CStr::from_bytes_until_nul(&write_syscall.buf)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        println!(
            "WRITE KERNEL: DATA {:?} FILENAME: {:?} STORED OFFSET: {:?} LEN: {:?}",
            write_syscall,
            filename,
            offset,
            contents.len()
        );
        let _ = self.resolved_files.send(FSTracerFile {
            timestamp: chrono::Utc::now().to_rfc3339(),
            absolute_path: filename.to_string(),
            contents: contents.to_string(),
            offset,
        });
        self.open_files
            .remove(&(write_syscall.fd, write_syscall.pid));
        self.open_files.insert(
            (write_syscall.fd, write_syscall.pid),
            (filename.clone(), offset + write_syscall.count),
        );
        Ok(())
    }

    fn handle_fseek(&mut self, fseek_syscall: FSeekSyscallBPF) -> Result<(), ()> {
        let (filename, offset) = match self.open_files.get(&(fseek_syscall.fd, fseek_syscall.pid)) {
            None => {
                println!(
                    "DIDNT FIND AN OPEN FILE FOR THE FSEEK SYSCALL (fd: {}, ret: {})",
                    fseek_syscall.fd, fseek_syscall.ret
                );
                return Ok(());
            }
            Some(str) => str.clone(),
        };
        println!(
            "FSEEK KERNEL: DATA {:?} FILENAME: {:?} STORED OFFSET: {:?}",
            fseek_syscall, filename, offset,
        );
        self.open_files
            .remove(&(fseek_syscall.fd, fseek_syscall.pid));

        //TODO: treat fseek_syscall.whence
        let final_offset: i64 = match fseek_syscall.whence {
            0 => fseek_syscall.offset,          //SEEK_SET
            1 => offset + fseek_syscall.offset, //SEEK_CUR
            2 => -1,                            //SEEK_END
            _ => panic!("Invalid whence value!"),
        };

        self.open_files.insert(
            (fseek_syscall.fd, fseek_syscall.pid),
            (filename.clone(), final_offset),
        );
        Ok(())
    }

    fn handle_open(&mut self, open_syscall: OpenSyscallBPF) -> Result<(), ()> {
        let filename = CStr::from_bytes_until_nul(&open_syscall.filename)
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        println!("OPEN KERNEL DATA: {:?}", open_syscall);
        println!("OPEN FILENAME: {:?}", filename);
        let fd = open_syscall.ret;
        self.open_files
            .insert((fd, open_syscall.pid), (filename.to_string(), 0));
        Ok(())
    }

    fn handle_close(&mut self, close_syscall: CloseSyscallBPF) -> Result<(), ()> {
        let filename = match self
            .open_files
            .remove(&(close_syscall.fd, close_syscall.pid))
        {
            None => {
                println!(
                    "DIDNT FIND AN OPEN FILE FOR THE CLOSE SYSCALL (fd: {})",
                    close_syscall.fd
                );
                return Ok(());
            }
            Some(str) => str,
        };
        println!("CLOSE KERNEL DATA: {:?}", close_syscall);
        println!("CLOSE FILENAME: {:?}", filename);
        Ok(())
    }
}
