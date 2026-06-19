#![no_std]
#![no_main]

use embassy_time::Duration;
use embassy_time::Instant;
use embassy_time::Timer;
use embassy_time::with_timeout;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::ieee802154::Ieee802154;
use zigbee::aps::aib;
use zigbee::nwk::nib::CapabilityInformation;
use zigbee::nwk::nlme::Nlme;
use zigbee::nwk::nlme::management::NlmeJoinStatus;
use zigbee_base_device_behavior::BaseDeviceBehavior;
use zigbee_base_device_behavior::types::BdbEvent;
use zigbee_cluster_library::ZigbeeDevice;
use zigbee_cluster_library::common::BasicConfig;
use zigbee_cluster_library::common::BasicServer;
use zigbee_cluster_library::common::IdentifyServer;
use zigbee_cluster_library::measurement::temperature::TemperatureMeasurementServer;
use zigbee_mac::esp::EspMlme;

esp_bootloader_esp_idf::esp_app_desc!();

/// Extended PAN ID of the network to join.
/// To auto-select, replace `network_steering(...)` with
/// `network_steering_any(...)`.
const EXTENDED_PAN_ID: u64 = 0xcbb6d82b6c609c25;

/// Channel to scan on (must match the coordinator's channel).
const CHANNEL: u8 = 20;

/// Scan duration exponent (beacon order).
const SCAN_DURATION: u8 = 5;

// ---------------------------------------------------------------------------
// Application device
// ---------------------------------------------------------------------------

#[derive(ZigbeeDevice)]
struct SensorDevice {
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 0)]
    #[zcl(server)]
    basic: BasicServer,
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 0)]
    #[zcl(server)]
    identify: IdentifyServer,
    #[zcl(endpoint = 1, profile = 0x0104, device = 0x0302, version = 0)]
    #[zcl(server)]
    temperature: TemperatureMeasurementServer,
}

impl SensorDevice {
    fn new() -> Self {
        let config = BasicConfig::new(
            3,              // ZCL version 3
            "Acme",         // ManufacturerName
            "TempSensor-1", // ModelIdentifier
            0x03,           // PowerSource: battery
            true,           // DeviceEnabled
        );
        Self {
            basic: BasicServer::new(config),
            identify: IdentifyServer::new(),
            temperature: TemperatureMeasurementServer::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Simulated thermistor read — replace with actual ADC/I2C peripheral read.
// ZCL unit: 0.01 °C, so 2250 = 22.50 °C.
// ---------------------------------------------------------------------------
fn read_thermistor() -> Option<i16> {
    Some(2250)
}

fn poll_timeout_from_tick(next_tick_ms: Option<u32>, now_ms: u32) -> Duration {
    const MAX_POLL_WAIT_MS: u32 = 60_000;
    let wait_ms = match next_tick_ms {
        Some(next) if now_ms.wrapping_sub(next) < 0x8000_0000 => 1,
        Some(next) => next.wrapping_sub(now_ms).min(MAX_POLL_WAIT_MS).max(1),
        None => MAX_POLL_WAIT_MS,
    };
    Duration::from_millis(u64::from(wait_ms))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    esp_alloc::heap_allocator!(size: 24 * 1024);

    zigbee::nwk::nib::init(zigbee::nwk::nib::NibStorage::default());
    zigbee::aps::aib::init(zigbee::aps::aib::AibStorage::default());

    let ieee802154 = Ieee802154::new(peripherals.IEEE802154);
    let mac = EspMlme::new(ieee802154, Default::default());
    let nwk = Nlme::new(mac);

    let config = zigbee::Config {
        device_type: zigbee::LogicalType::EndDevice,
        ..zigbee::Config::default()
    };
    let mut bdb = BaseDeviceBehavior::new(nwk, config);
    let mut device = SensorDevice::new();

    println!("Joining EPID={EXTENDED_PAN_ID:#018x} on channel {CHANNEL}...");
    match bdb
        .network_steering_any(
            // IeeeAddress(EXTENDED_PAN_ID),
            CHANNEL..CHANNEL + 4,
            SCAN_DURATION,
            CapabilityInformation(0x80),
        )
        .await
    {
        Ok(confirm) if confirm.status == NlmeJoinStatus::Success => {
            let nib = bdb.nib();
            println!(
                "Joined: addr={:#06x} pan={:#06x} epid={:#x} update_id={}",
                nib.network_address(),
                nib.panid(),
                nib.extended_panid(),
                nib.update_id()
            );

            let network_key = nib.security_material_set().first().unwrap().key;
            println!("Network key installed: key={:02x?}", network_key);

            let link_key = aib::get_ref()
                .device_key_pair_set()
                .first()
                .unwrap()
                .link_key;
            println!("Link key installed: key={:02x?}", link_key);
        }
        Ok(confirm) => {
            println!("Join failed: {:?} — halting", confirm.status);
            loop {
                Timer::after(Duration::from_secs(3600)).await;
            }
        }
        Err(e) => {
            println!("Join error: {e:#} — halting");
            loop {
                Timer::after(Duration::from_secs(3600)).await;
            }
        }
    }

    loop {
        let now_ms = Instant::now().as_millis() as u32;

        if let Err(e) = device.temperature.set_measured_value(read_thermistor()) {
            println!("Temperature update error: {e:?}");
        }

        // Application LED/blink: illuminate while coordinator is identifying this
        // device. (tick is driven by poll_once internally)
        if device.identify.remaining() > 0 {
            println!("Identifying: {}s remaining", device.identify.remaining());
        }

        let poll_timeout = poll_timeout_from_tick(bdb.last_device_tick().next_tick_ms, now_ms);
        // Dispatch one incoming frame (also drives device.tick internally).
        match with_timeout(poll_timeout, bdb.poll_once(&mut device, now_ms)).await {
            Ok(Ok(BdbEvent::ZclHandled { response_sent, .. })) => {
                println!("ZCL handled (response_sent={response_sent})");
            }
            Ok(Ok(BdbEvent::TransportKeyInstalled)) => {
                println!("Transport key installed");
            }
            Ok(Ok(BdbEvent::Joined)) => {
                println!("On network");
            }
            Ok(Ok(BdbEvent::Rejoined)) => {
                println!("Rejoined network");
            }
            Ok(Ok(BdbEvent::Left { rejoin })) => {
                println!("Network requested leave (rejoin={rejoin}) — halting");
                loop {
                    Timer::after(Duration::from_secs(3600)).await;
                }
            }
            Ok(Ok(BdbEvent::DeviceAnnounced(_))) | Ok(Ok(BdbEvent::ZdoResponse { .. })) => {}
            Ok(Ok(BdbEvent::UnsupportedFrame)) => {}
            Ok(Err(e)) => {
                println!("BDB error: {e:#}");
            }
            Err(_timeout) => {}
        }

        // Send one pending attribute report if any.
        if let Err(e) = bdb.poll_report_once(&mut device, now_ms).await {
            println!("Report error: {e:#}");
        }
    }
}
