use std::error::Error;

extern crate zip;
use crate::api::ADResults;
use crate::args::Options;
use crate::utils::date::return_current_fulldate;
pub mod common;

pub fn make_result(common_args: &Options, ad_results: ADResults) -> Result<String, Box<dyn Error>> {
    let domain_part = common_args.domain.replace('.', "-").to_lowercase();
    let datetime = return_current_fulldate();

    let filename = match &common_args.output_prefix {
        Some(prefix) => format!("{}_{}", prefix.replace(' ', "_"), domain_part),
        None => domain_part,
    };

    if common_args.zip {
        return common::make_a_zip(&datetime, &filename, &common_args.path, &ad_results);
    }

    common::write_json_files(&datetime, &filename, common_args, &ad_results)?;
    Ok(common_args.path.clone())
}
