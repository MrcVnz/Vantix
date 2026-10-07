//! Real-time ETW sessions, the way Windows reports what drivers and runtimes do without
//! hooking anything. A session outlives the process that started it, so each one is
//! stopped by name before a start and when Vantix exits.

use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace,
    StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, HSTRING, PWSTR, Result};

pub struct Provider {
    pub guid: GUID,
    /// 4 is TRACE_LEVEL_INFORMATION.
    pub level: u8,
    pub keywords: u64,
    /// Only these event ids reach the session, filtered by Windows before they cost
    /// anything here. Empty lets every event of the keywords through.
    pub events: &'static [u16],
}

pub type Callback = unsafe extern "system" fn(*mut EVENT_RECORD);

#[repr(C)]
struct Properties {
    base: EVENT_TRACE_PROPERTIES,
    name: [u16; 64],
}

/// `buffer_kb` and `max_buffers` size the session for its event rate: buffers that fill
/// up drop events.
fn properties(buffer_kb: u32, max_buffers: u32) -> Properties {
    let mut properties = Properties { base: EVENT_TRACE_PROPERTIES::default(), name: [0; 64] };
    properties.base.Wnode.BufferSize = size_of::<Properties>() as u32;
    properties.base.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.base.Wnode.ClientContext = 1; // QPC timestamps
    properties.base.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties.base.FlushTimer = 1;
    properties.base.BufferSize = buffer_kb;
    properties.base.MinimumBuffers = 8;
    properties.base.MaximumBuffers = max_buffers;
    properties.base.LoggerNameOffset = std::mem::offset_of!(Properties, name) as u32;
    properties
}

pub fn stop(name: &str) {
    let mut properties = properties(0, 0);
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            &HSTRING::from(name),
            &mut properties.base,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Starts the session and a thread that hands every event to `callback` until `stop`.
/// Needs admin rights, which Vantix always has. Events start arriving a couple of seconds
/// later and then come in batches, once a second.
pub fn start(name: &str, providers: &[Provider], buffer_kb: u32, max_buffers: u32, callback: Callback) -> Result<()> {
    stop(name);
    let mut properties = properties(buffer_kb, max_buffers);
    let mut handle = CONTROLTRACE_HANDLE::default();
    unsafe {
        StartTraceW(&mut handle, &HSTRING::from(name), &mut properties.base).ok()?;
        for provider in providers {
            // EVENT_FILTER_EVENT_ID: filter in, a reserved byte, the count, then the ids.
            let mut ids: Vec<u8> = vec![1, 0];
            ids.extend((provider.events.len() as u16).to_le_bytes());
            ids.extend(provider.events.iter().flat_map(|id| id.to_le_bytes()));
            let mut filter = EVENT_FILTER_DESCRIPTOR {
                Ptr: ids.as_ptr() as u64,
                Size: ids.len() as u32,
                Type: EVENT_FILTER_TYPE_EVENT_ID,
            };
            let parameters = ENABLE_TRACE_PARAMETERS {
                Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
                EnableFilterDesc: &mut filter,
                FilterDescCount: 1,
                ..Default::default()
            };
            let enabled = EnableTraceEx2(
                handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                provider.level,
                provider.keywords,
                0,
                0,
                (!provider.events.is_empty()).then_some(&raw const parameters),
            );
            if let Err(e) = enabled.ok() {
                stop(name);
                return Err(e);
            }
        }
    }
    consume(name, callback)
}

/// Starts a private session for kernel events, the ones the "NT Kernel Logger" carries,
/// without taking that single shared session from other tools. `flags` picks the event
/// groups (EVENT_TRACE_FLAG_*).
pub fn start_kernel(name: &str, flags: EVENT_TRACE_FLAG, buffer_kb: u32, max_buffers: u32, callback: Callback) -> Result<()> {
    stop(name);
    let mut properties = properties(buffer_kb, max_buffers);
    properties.base.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties.base.EnableFlags = flags;
    let mut handle = CONTROLTRACE_HANDLE::default();
    unsafe { StartTraceW(&mut handle, &HSTRING::from(name), &mut properties.base).ok()? };
    consume(name, callback)
}

/// Opens the session for reading on a thread that runs until the session stops.
fn consume(name: &str, callback: Callback) -> Result<()> {
    let mut logger: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut logfile = EVENT_TRACE_LOGFILEW { LoggerName: PWSTR(logger.as_mut_ptr()), ..Default::default() };
    // Raw timestamps are QueryPerformanceCounter ticks; without the flag Windows turns
    // them into wall clock time, which jumps when the clock is set.
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Anonymous2.EventRecordCallback = Some(callback);
    unsafe {
        let trace = OpenTraceW(&mut logfile);
        if trace.Value == u64::MAX {
            let error = windows::core::Error::from_thread();
            stop(name);
            return Err(error);
        }
        std::thread::spawn(move || {
            let _ = ProcessTrace(&[trace], None, None);
            let _ = CloseTrace(trace);
        });
    }
    Ok(())
}

/// The event's payload as bytes; empty when it has none.
pub fn payload(record: &EVENT_RECORD) -> &[u8] {
    if record.UserData.is_null() {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), usize::from(record.UserDataLength)) }
}
