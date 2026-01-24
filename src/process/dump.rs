use crate::{
    file::{self, Exists},
    helpers, log,
    process::{Runner, id::Id},
};

use chrono::Utc;
use colored::Colorize;
use global_placeholders::global;
use macros_rs::{crashln, fmtstr, string};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use std::{collections::BTreeMap, fs};

/// Helper function to create an empty Runner
fn empty_runner() -> Runner {
    Runner {
        id: Id::new(0),
        list: BTreeMap::new(),
        remote: None,
    }
}

/// Helper function to read permanent dump with fallback to empty runner
fn read_permanent_dump() -> Runner {
    if !Exists::check(&global!("opm.dump")).file() {
        let runner = empty_runner();
        write(&runner);
        log!("created dump file");
        return runner;
    }

    match file::try_read_object(global!("opm.dump")) {
        Ok(runner) => runner,
        Err(err) => {
            log!("[dump] Failed to read permanent dump: {err}");
            let runner = empty_runner();
            write(&runner);
            runner
        }
    }
}

pub fn from(address: &str, token: Option<&str>) -> Result<Runner, anyhow::Error> {
    let client = Client::new();
    let mut headers = HeaderMap::new();

    if let Some(token) = token {
        headers.insert(
            "token",
            HeaderValue::from_static(Box::leak(Box::from(token))),
        );
    }

    let response = client
        .get(fmtstr!("{address}/daemon/dump"))
        .headers(headers)
        .send()?;
    let bytes = response.bytes()?;

    Ok(file::from_object(&bytes))
}

pub fn read() -> Runner {
    if !Exists::check(&global!("opm.dump")).file() {
        let runner = Runner {
            id: Id::new(0),
            list: BTreeMap::new(),
            remote: None,
        };

        write(&runner);
        log!("created dump file");
        return runner;
    }

    // Try to read the dump file with error recovery
    match file::try_read_object(global!("opm.dump")) {
        Ok(runner) => runner,
        Err(err) => {
            // If parsing fails, the dump file is likely corrupted
            // Log the error and create a fresh dump file
            log!("[dump::read] Corrupted dump file detected: {err}");

            // Backup the corrupted file for debugging
            let backup_path = format!(
                "{}.corrupted.{}",
                global!("opm.dump"),
                Utc::now().format("%Y%m%d_%H%M%S")
            );

            // Try rename first (fast for same filesystem), fall back to copy+remove for cross-filesystem
            let backup_result = fs::rename(global!("opm.dump"), &backup_path).or_else(|_| {
                fs::copy(global!("opm.dump"), &backup_path)
                    .and_then(|_| fs::remove_file(global!("opm.dump")))
            });

            if let Err(e) = backup_result {
                log!("[dump::read] Failed to backup corrupted file: {e}");
            } else {
                log!("[dump::read] Backed up corrupted file to: {backup_path}");
            }

            // Create a fresh runner with empty state
            let runner = Runner {
                id: Id::new(0),
                list: BTreeMap::new(),
                remote: None,
            };

            write(&runner);
            log!("[dump::read] Created fresh dump file after corruption");

            runner
        }
    }
}

pub fn raw() -> Vec<u8> {
    if !Exists::check(&global!("opm.dump")).file() {
        let runner = empty_runner();
        write(&runner);
        log!("created dump file");
    }

    file::raw(global!("opm.dump"))
}

pub fn write(dump: &Runner) {
    let encoded = match ron::ser::to_string(&dump) {
        Ok(contents) => contents,
        Err(err) => crashln!(
            "{} Cannot encode dump.\n{}",
            *helpers::FAIL,
            string!(err).white()
        ),
    };

    if let Err(err) = fs::write(global!("opm.dump"), encoded) {
        crashln!(
            "{} Error writing dumpfile.\n{}",
            *helpers::FAIL,
            string!(err).white()
        )
    }
}

/// Read from temporary dump file
pub fn read_temp() -> Runner {
    if !Exists::check(&global!("opm.dump.temp")).file() {
        return empty_runner();
    }

    match file::try_read_object(global!("opm.dump.temp")) {
        Ok(runner) => runner,
        Err(err) => {
            log!("[dump::read_temp] Failed to read temp dump: {err}");
            empty_runner()
        }
    }
}

/// Write to temporary dump file
pub fn write_temp(dump: &Runner) {
    let encoded = match ron::ser::to_string(&dump) {
        Ok(contents) => contents,
        Err(err) => {
            log!("[dump::write_temp] Cannot encode temp dump: {err}");
            return;
        }
    };

    if let Err(err) = fs::write(global!("opm.dump.temp"), encoded) {
        log!("[dump::write_temp] Error writing temp dumpfile: {err}");
    }
}

/// Merge temporary dump into permanent and clear temporary
pub fn commit_temp() {
    // Read permanent dump directly
    let mut permanent = read_permanent_dump();
    let temporary = read_temp();
    
    // Merge temporary processes into permanent
    for (id, process) in temporary.list {
        permanent.list.insert(id, process);
    }
    
    // Update ID counter to maximum
    use std::sync::atomic::Ordering;
    let temp_counter = temporary.id.counter.load(Ordering::SeqCst);
    let perm_counter = permanent.id.counter.load(Ordering::SeqCst);
    if temp_counter > perm_counter {
        permanent.id.counter.store(temp_counter, Ordering::SeqCst);
    }
    
    // Write merged state to permanent
    write(&permanent);
    
    // Clear temporary dump
    let _ = fs::remove_file(global!("opm.dump.temp"));
    log!("[dump::commit_temp] Committed temporary processes to permanent storage");
}

/// Read merged state (permanent + temporary)
pub fn read_merged() -> Runner {
    // Read permanent dump directly without triggering recursive operations
    let mut permanent = read_permanent_dump();
    
    // Read temporary dump if it exists
    let temporary = read_temp();
    
    // Merge temporary processes into permanent
    for (id, process) in temporary.list {
        permanent.list.insert(id, process);
    }
    
    // Use maximum ID counter
    use std::sync::atomic::Ordering;
    let temp_counter = temporary.id.counter.load(Ordering::SeqCst);
    let perm_counter = permanent.id.counter.load(Ordering::SeqCst);
    if temp_counter > perm_counter {
        permanent.id.counter.store(temp_counter, Ordering::SeqCst);
    }
    
    permanent
}

/// Initialize on daemon startup: merge temp into permanent, set crashed to stopped, clean temp
pub fn init_on_startup() -> Runner {
    // Read permanent and temp
    let mut permanent = read_permanent_dump();
    
    // Merge temp dump if it exists
    let temp_dump_path = global!("opm.dump.temp");
    if Exists::check(&temp_dump_path).file() {
        log!("[dump::init_on_startup] Found temp dump file, merging...");
        let temporary = read_temp();
        
        // Merge temporary processes into permanent
        for (id, process) in temporary.list {
            permanent.list.insert(id, process);
        }
        
        // Update ID counter to maximum
        use std::sync::atomic::Ordering;
        let temp_counter = temporary.id.counter.load(Ordering::SeqCst);
        let perm_counter = permanent.id.counter.load(Ordering::SeqCst);
        if temp_counter > perm_counter {
            permanent.id.counter.store(temp_counter, Ordering::SeqCst);
        }
        
        // Delete temp file after merging
        let _ = fs::remove_file(&temp_dump_path);
        log!("[dump::init_on_startup] Merged and cleaned up temp dump file");
    }

    // Set all crashed processes to stopped status
    for (_id, process) in permanent.list.iter_mut() {
        if process.crash.crashed {
            process.running = false;
            process.crash.crashed = false;
            log!("[dump::init_on_startup] Set crashed process '{}' to stopped", process.name);
        }
    }

    permanent
}

