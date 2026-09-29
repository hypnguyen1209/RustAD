#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use env_logger::Builder;
use log::{error, info, trace};

use rustad::{api::run_collection, args, banner, transport::ldap::ldap_auth};
use std::error::Error;

#[cfg(feature = "noargs")]
use args::auto_args;
#[cfg(not(feature = "noargs"))]
use args::{extract_args, Options};

use banner::{print_banner, print_end_banner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_banner();

    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    Builder::new()
        .filter(Some("rustad"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    let mut ldap = ldap_auth(&common_args).await?;

    match run_collection(&mut ldap, &common_args).await {
        Ok(out) => trace!("Output written to {out}"),
        Err(err) => error!("Collection failed. Reason: {err}"),
    }

    if common_args.session_loop && common_args.collection_method.does_sessions() {
        info!(
            "Session loop enabled: duration={}s, interval={}s",
            common_args.loop_duration, common_args.loop_interval
        );
        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_secs(common_args.loop_duration);
        let interval = std::time::Duration::from_secs(common_args.loop_interval);
        let mut iteration = 1u32;

        while start.elapsed() < duration {
            tokio::time::sleep(interval).await;
            iteration += 1;
            info!(
                "Session loop iteration #{} ({:.0}s elapsed)",
                iteration,
                start.elapsed().as_secs_f64()
            );
            match run_collection(&mut ldap, &common_args).await {
                Ok(out) => trace!("Loop #{iteration} output: {out}"),
                Err(err) => error!("Loop #{iteration} failed: {err}"),
            }
        }
        info!("Session loop completed after {} iterations", iteration);
    }

    let _ = ldap.unbind().await;

    print_end_banner();
    Ok(())
}
