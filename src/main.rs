#![allow(dead_code)]

mod find_vuln;
mod utils;
mod driver_policy;

use clap::Parser;

use log::{error, info, warn, LevelFilter};
use simplelog::{ColorChoice, CombinedLogger, Config as LogConfig, TermLogger, TerminalMode};
use std::error::Error;
use std::path::Path;
use std::fs;
use crate::find_vuln::analyze_single_driver;

#[derive(Parser)]
#[clap(name = "Driver Vulnerability Analyzer", version = "1.0", author = "BlackSnufkin")]
struct Args {
    #[clap(short = 'd', long = "driver", help = "Path to the driver file (.sys) to analyze")]
    driver_file: Option<String>,
    
    #[clap(short = 'D', long = "directory", help = "Directory containing driver files to analyze")]
    driver_directory: Option<String>,
    
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

fn is_driver_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()).map(|ext| ext.to_lowercase()).as_deref() {
        Some("sys") | Some("dll") => true,
        _ => false,
    }
}

fn analyze_directory(directory: &str, output_dir: &str, policy_dir: &str, json_output: bool) -> Result<(), Box<dyn Error>> {
    let dir_path = Path::new(directory);
    
    if !dir_path.exists() {
        return Err(format!("Directory does not exist: {}", directory).into());
    }
    
    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", directory).into());
    }
    
    info!("Scanning directory: {}", directory);
    
    let entries = fs::read_dir(dir_path)?;
    let mut driver_files = Vec::new();
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && is_driver_file(&path) {
            driver_files.push(path.to_string_lossy().into_owned());
        }
    }
    
    if driver_files.is_empty() {
        warn!("No driver files found in directory: {}", directory);
        return Ok(());
    }
    
    info!("Found {} driver files to analyze", driver_files.len());
    
    let mut successful = 0;
    let mut failed = 0;
    
    for driver_path in driver_files {
        info!("Analyzing: {}", driver_path);
        
        match analyze_single_driver(&driver_path, output_dir, policy_dir, json_output) {
            Ok(()) => {
                successful += 1;
                info!("✓ Successfully analyzed: {}", driver_path);
            },
            Err(e) => {
                failed += 1;
                error!("✗ Failed to analyze {}: {}", driver_path, e);
            }
        }
    }
    
    info!("Directory analysis complete. Successful: {}, Failed: {}", successful, failed);
    Ok(())
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
    
    // Validate input arguments
    match (&args.driver_file, &args.driver_directory) {
        (Some(_), Some(_)) => {
            return Err("Cannot specify both --driver and --directory".into());
        },
        (None, None) => {
            return Err("Must specify either --driver or --directory".into());
        },
        _ => {}
    }
    
    info!("Starting Driver Vulnerability Analysis");
    info!("Output: {}", args.output_directory);
    info!("Policy directory: {}", args.policy_directory);
    info!("Format: {}", if args.json_output { "JSON" } else { "Text" });
    
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
    
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output_directory)?;
    
    // Process either single driver or directory
    if let Some(driver_file) = &args.driver_file {
        // Single driver analysis (existing functionality)
        let driver_path = Path::new(driver_file);
        
        if !driver_path.exists() {
            error!("Driver file does not exist: {}", driver_file);
            return Err("Driver file not found".into());
        }
        
        if !driver_path.is_file() {
            error!("Input path is not a file: {}", driver_file);
            return Err("Input must be a driver file, not a directory".into());
        }
        
        if !is_driver_file(driver_path) {
            error!("Invalid file extension. Driver file must have .sys or .dll extension");
            return Err("Invalid driver file extension".into());
        }
        
        info!("Analyzing single driver: {}", driver_file);
        
        match analyze_single_driver(driver_file, &args.output_directory, &args.policy_directory, args.json_output) {
            Ok(()) => {
                info!("Analysis completed successfully!");
            },
            Err(e) => {
                error!("Analysis failed: {}", e);
                return Err(e);
            }
        }
        
    } else if let Some(driver_directory) = &args.driver_directory {
        // Directory analysis (new functionality)
        match analyze_directory(driver_directory, &args.output_directory, &args.policy_directory, args.json_output) {
            Ok(()) => {
                info!("Directory analysis completed!");
            },
            Err(e) => {
                error!("Directory analysis failed: {}", e);
                return Err(e);
            }
        }
    }
    
    Ok(())
}