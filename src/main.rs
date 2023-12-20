extern crate rbpf;

use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

fn load_fletcher32_program() -> Vec<u8> {
    // Hardcoded program bytes because I can't figure out a way to easily load
    // the ebpf byte code from a file. Possible options would be to host a http
    // server and accept the bytes in a post request. or set up a file system
    // on the microcontroller (e.g. SPIFFS or littlefs).
    [183, 0, 0, 0, 46, 5, 135, 46, 149, 0, 0, 0, 0, 0, 0, 0].to_vec()
}

fn fletcher32_native() -> u32 {
    let message = r#"This is a test message for the Fletcher32 checksum algorithm.\n"#;

    let mut length = message.len() / 2;

    let mut c0: u32 = 0;
    let mut c1: u32 = 0;

    // Checksum magic
    while length > 0 {
        let mut blocklen: usize = length;
        if blocklen > 360 * 2 {
            blocklen = 360 * 2;
        }
        length -= blocklen;
        for i in (0..blocklen).step_by(2) {
            let c;
            unsafe {
                c = *message.as_bytes().get_unchecked(i);
            }
            c0 = c0 + c as u32;
            c1 = c1 + c0;
        }
        c0 = c0 % 65535;
        c1 = c1 % 65535;
    }

    let checksum = c1 << 16 | c0;

    return checksum;
}

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let prog = load_fletcher32_program();

    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();

    let now = Instant::now();
    let res = vm.execute_program().unwrap();
    let elapsed = now.elapsed();
    log::info!("Program returned: {:?} ({:#x})", res, res);
    log::info!("Elapsed: {:.2?}", elapsed);

    let now = Instant::now();
    let checksum = fletcher32_native();
    let elapsed = now.elapsed();
    log::info!(
        "Natively calculated checksum: {:?} ({:#x})",
        checksum,
        checksum
    );
    log::info!("Elapsed: {:.2?}", elapsed);

    let iterations = 1000;
    loop {
        let mut vm_times: Vec<Duration> = Vec::new();
        let mut native_times: Vec<Duration> = Vec::new();

        for _ in 0..iterations {
            let (vm_time, native_time) = benchmark_iteration(&prog);
            //log::info!("Native: {:.2?}, VM: {:.2?}", native_time, vm_time);
            vm_times.push(vm_time);
            native_times.push(native_time);
        }

        let vm_avg = vm_times.iter().sum::<Duration>() / iterations;
        let native_avg = native_times.iter().sum::<Duration>() / iterations;

        log::info!(
            "Average native: {:.2?}, Average VM: {:.2?}",
            native_avg,
            vm_avg
        );
        sleep(Duration::from_millis(10000));
    }
}

fn benchmark_iteration(prog: &Vec<u8>) -> (Duration, Duration) {
    let now = Instant::now();
    // Decided to move the vm initialisation here as it should be
    // classified as a part of the execution time.
    let vm = rbpf::EbpfVmNoData::new(Some(prog)).unwrap();
    let res = vm.execute_program().unwrap();
    let elapsed1 = now.elapsed();

    let now = Instant::now();
    let checksum = fletcher32_native();
    let elapsed2 = now.elapsed();

    assert_eq!(res, checksum.into(), "Checksum values don't match");
    return (elapsed1, elapsed2);
}
