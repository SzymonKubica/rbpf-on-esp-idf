use esp_idf_svc::{
    hal::{gpio::AnyIOPin, peripherals::Peripherals, units::Hertz},
    sys::sleep,
};
use rbpf::{EbpfVmMbuff, EbpfVmNoData};
use std::fmt::Write;

extern crate rbpf;

// Task 1: support loading arbitary ebpf code that doesn't take any packet
// data as input.

fn test_ebpf_vm_no_data() {
    // This is the eBPF program, in the form of bytecode instructions.
    let prog = &[
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
        0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
        0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    // Instantiate a struct EbpfVmNoData. This is an eBPF VM for programs that
    // takes no packet data in argument.
    // The eBPF program is passed to the constructor.
    let vm = EbpfVmNoData::new(Some(prog)).unwrap();

    // Execute (interpret) the program. No argument required for this VM.
    let result = vm.execute_program().unwrap();
    assert_eq!(result, 0x3);
    log::info!("{}", result)
}

fn test_ebpf_vm_buff() {
    let prog = &[
        // Load mem from mbuff at offset 8 into R1
        0x79, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ldhx r1[2], r0
        0x69, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mem = &mut [0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd];

    // Just for the example we create our metadata buffer from scratch, and
    // we store the pointers to packet data start and end in it.
    let mut mbuff = &mut [0u8; 32];
    unsafe {
        let mut data = mbuff.as_ptr().offset(8) as *mut u64;
        let mut data_end = mbuff.as_ptr().offset(24) as *mut u64;
        *data = mem.as_ptr() as u64;
        *data_end = mem.as_ptr() as u64 + mem.len() as u64;
    }

    // This eBPF VM is for program that use a metadata buffer.
    let mut vm = EbpfVmMbuff::new(Some(prog)).unwrap();
    let result = vm.execute_program(mem, mbuff).unwrap();
    assert_eq!(result, 0x2211);
    log::info!("{}", result)
}

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().unwrap();
    let pins = peripherals.pins;

    let config = esp_idf_svc::hal::uart::config::Config::default().baudrate(Hertz(115_200));

    let mut uart: esp_idf_svc::hal::uart::UartDriver = esp_idf_svc::hal::uart::UartDriver::new(
        peripherals.uart1,
        pins.gpio1,
        pins.gpio3,
        Option::<AnyIOPin>::None,
        Option::<AnyIOPin>::None,
        &config,
    )
    .unwrap();

    loop {
        for i in 0..10 {
            writeln!(uart, "{:}", format!("count {:}", i)).unwrap();
        }

        log::info!("Hello, world!");
        test_ebpf_vm_no_data();
        test_ebpf_vm_buff();
        unsafe {
            sleep(1000);
        }
    }
}
