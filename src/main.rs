mod find_vuln;
mod utils;
mod driver_policy;
use clap::Parser;
use log::{error, info, LevelFilter};
use simplelog::{ColorChoice, CombinedLogger, Config as LogConfig, TermLogger, TerminalMode};
use std::error::Error;
use std::path::Path;
use crate::find_vuln::analyze_single_driver;

#[derive(Parser)]
#[clap(name = "Driver Vulnerability Analyzer", version = "1.0", author = "BlackSnufkin")]
#[clap(about = "BYOVD hunter for identifying Windows drivers suitable for exploitation.")]
struct Args {
    #[clap(short = 'd', long = "driver", help = "Path to the driver file (.sys) to analyze")]
    driver_file: String,
    
    #[clap(short = 'o', long = "output", help = "Output directory for analysis results")]
    #[clap(default_value = ".\\Analysis")]
    output_directory: String,
    
    #[clap(short = 'p', long = "policies", help = "Path to directory containing policy files")]
    #[clap(default_value = "Policies")]
    policy_directory: String,
    
    #[clap(short = 'j', long = "json", help = "Output results in JSON format instead of text")]
    json_output: bool,
    
    #[clap(short = 'v', long = "verbose", help = "Enable verbose logging")]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    // Setup logging
    CombinedLogger::init(vec![TermLogger::new(
        if args.verbose { LevelFilter::Debug } else { LevelFilter::Info },
        LogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])?;
    
    info!("Starting Driver Vulnerability Analysis");
    info!("Driver file: {}", args.driver_file);
    info!("Output: {}", args.output_directory);
    info!("Policy directory: {}", args.policy_directory);
    info!("Format: {}", if args.json_output { "JSON" } else { "Text" });
    
    // Validate input file
    let driver_path = Path::new(&args.driver_file);
    if !driver_path.exists() {
        error!("Driver file does not exist: {}", args.driver_file);
        return Err("Driver file not found".into());
    }
    
    if !driver_path.is_file() {
        error!("Input path is not a file: {}", args.driver_file);
        return Err("Input must be a driver file, not a directory".into());
    }
    
    // Validate policy directory
    let policy_path = Path::new(&args.policy_directory);
    if !policy_path.exists() {
        error!("Policy directory does not exist: {}", args.policy_directory);
        return Err("Policy directory not found".into());
    }
    
    if !policy_path.is_dir() {
        error!("Policy path is not a directory: {}", args.policy_directory);
        return Err("Policy path must be a directory".into());
    }
    
    // Validate file extension
    match driver_path.extension().and_then(|ext| ext.to_str()).map(|ext| ext.to_lowercase()).as_deref() {
        Some("sys") | Some("dll") => {
            info!("Analyzing driver file: {}", driver_path.display());
        },
        Some(ext) => {
            error!("Unsupported file extension: .{}", ext);
            return Err("Driver file must have .sys or .dll extension".into());
        },
        None => {
            error!("No file extension found");
            return Err("Driver file must have .sys or .dll extension".into());
        }
    }
    
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output_directory)?;
    
    // Run vulnerability analysis
    match analyze_single_driver(&args.driver_file, &args.output_directory, &args.policy_directory, args.json_output) {
        Ok(()) => {
            info!("Analysis completed successfully!");
        },
        Err(e) => {
            error!("Analysis failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}