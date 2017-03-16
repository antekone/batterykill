#![allow(unused_variables)]

extern crate regex;
extern crate libc;

use std::io::Read;
use std::str;
use libc::SIGTERM;

fn check_path(pid: i32) -> bool {
    let path = format!("/proc/{}/cmdline", pid);
    let mut rdr = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut buf = Vec::new();

    rdr.read_to_end(&mut buf).expect("can't read cmdline");

    let spaced_buf = buf.iter().map(|&x| match x {
        0 => 0x20,
        x => x,
    }).collect::<Vec<u8>>();

    // Bug: code assumes system operates in UTF-8, but that can not be the case.
    let cmdline = str::from_utf8(&spaced_buf).unwrap();

    // Bad code: this regex should be created once and just passed over this function
    // in the argument (or some kind of context struct).
    let bat_matcher = regex::Regex::new(r".*wrapper.* .*xfce.*libbattery.so.*").unwrap();

    bat_matcher.is_match(cmdline)
}

fn find_battery_pid() -> Result<i32, String> {
    let pid_matcher = regex::Regex::new(r"^.+/(\d+)$").unwrap();

    for process_item in std::fs::read_dir("/proc").unwrap() {
        let dir_entry = process_item.unwrap();
        let path = dir_entry.path();
        let path_str = path.as_path().to_str().unwrap();

        let caps = match pid_matcher.captures(path_str) {
            Some(captures) => captures,
            None => continue,
        };

        let pid = i32::from_str_radix(caps.get(1).unwrap().as_str(), 10).unwrap();
        if pid < 2 {
            continue;
        }

        if check_path(pid) {
            return Ok(pid);
        }
    }

    Err("search function didn't find any matching process".to_string())
}

fn kill_process(pid: i32) -> bool {
    unsafe {
        libc::kill(pid, SIGTERM) == 0
    }
}

fn main() {
    let bpid = match find_battery_pid() {
        Ok(pid) => pid,
        Err(err_str) => {
            println!("Can't find battery panel ({}), aborting.", err_str);
            return;
        }
    };

    if !kill_process(bpid) {
        println!("Can't kill process {}, aborting.", bpid);
        return;
    }
}
