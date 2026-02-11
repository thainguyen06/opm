# OPM Fixes Summary

## Changes Made

### 1. Fixed Daemon Crash Monitoring (`src/daemon/mod.rs`)
- **Problem**: The daemon was skipping crash detection entirely when PID info was missing, preventing auto-restart of crashed processes.
- **Solution**: Modified `restart_process()` to treat processes with missing PID info as crashed if they should be running, allowing the restart logic to proceed.
- **Lines changed**: 131-152

### 2. Removed Automatic Permanent Saves in CLI Restore (`src/cli/internal.rs`)
- **Problem**: The CLI restore function was calling `save_permanent()` which writes to `process.dump` even without explicit user request.
- **Solution**: Changed to call `save()` instead, which only saves to memory cache, preventing unwanted disk writes.
- **Lines changed**: 1508-1512

### 3. Removed Automatic Permanent Saves in Daemon API Restore (`src/daemon/api/routes.rs`)
- **Problem**: The daemon API restore handler was calling `save_permanent()` after restore operations.
- **Solution**: Changed to call `save()` instead, maintaining consistency with the CLI behavior.
- **Lines changed**: 936-940

### 4. Fixed `read_permanent_dump()` to Avoid Creating Files (`src/process/dump.rs`)
- **Problem**: The function was creating `process.dump` files when they didn't exist or were corrupted, violating the principle of only writing on explicit saves.
- **Solution**: Modified to return empty runners without writing files, aligning with the new behavior.
- **Lines changed**: 64-85

### 5. Fixed Public `read()` Function for Consistency (`src/process/dump.rs`)
- **Problem**: The public `read()` function was also creating files when they didn't exist.
- **Solution**: Modified to return empty runners without writing files, maintaining consistency.
- **Lines changed**: 218-230

## Behavior Changes

### Before
1. **Crash Detection**: Processes with missing PID info were completely ignored by the daemon's crash detection
2. **File Creation**: `process.dump` was created/modified during restore operations and read operations
3. **State Persistence**: Process state was persisted to disk frequently, not just on explicit saves

### After
1. **Crash Detection**: Processes with missing PID info are treated as crashed (if they should be running) and will be auto-restarted
2. **File Creation**: `process.dump` is only created/modified on explicit `opm save` commands or daemon shutdown
3. **State Persistence**: Process state is primarily maintained in memory, with disk persistence only for explicit operations

## Testing Recommendations

1. **Crash Auto-Restart Test**:
   - Start a process that crashes
   - Verify the daemon detects the crash and auto-restarts it
   - Check that the crash counter increments appropriately

2. **Restore Behavior Test**:
   - Run `opm restore`
   - Verify `process.dump` is not modified unless explicitly saved
   - Check that processes are restored and running correctly

3. **Explicit Save Test**:
   - Run `opm save`
   - Verify `process.dump` is created/modified
   - Check that the file contains the current process state

4. **Daemon Shutdown Test**:
   - Stop the daemon (e.g., `opm daemon stop`)
   - Verify `process.dump` is created/modified with the final state
   - Restart daemon and verify processes are restored correctly

## Files Modified

1. `src/daemon/mod.rs` - Daemon crash monitoring logic
2. `src/cli/internal.rs` - CLI restore command
3. `src/daemon/api/routes.rs` - API restore endpoint
4. `src/process/dump.rs` - Process dump file handling

## Backward Compatibility

The changes maintain backward compatibility:
- Existing `process.dump` files can still be read
- Daemon shutdown still persists state (as expected)
- Explicit `opm save` commands work as before
- The only behavioral change is that restore operations no longer automatically persist to disk