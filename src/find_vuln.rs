use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use win32_version_info::VersionInfo;
use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use crate::utils::{DriverInfo, DANGEROUS_IMPORTS, COMMUNICATION_IMPORTS, calculate_file_hash, format_file_size, sanitize_version_string};
use crate::driver_policy::{load_policy, msft_block_policy, DriverPolicy, BlockingDetails};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverAnalysis {
    pub name: String,
    pub architecture: String,
    pub path: String,
    pub size: String,
    pub file_version: String,
    pub original_filename: String,  // ADD THIS FIELD
    pub sha256: String,
    pub critical_imports: Vec<String>,
    pub is_loldriver: bool,
    pub is_win10_blocked: bool,
    pub win10_block_reason: String,
    pub win10_blocking_details: Option<BlockingDetails>,
    pub is_win11_blocked: bool,
    pub win11_block_reason: String,
    pub win11_blocking_details: Option<BlockingDetails>,
    pub has_terminate_process: bool,
    pub has_communication: bool,
}

impl DriverAnalysis {
    fn from_driver_info(driver: &DriverInfo, hash: String, is_loldriver: bool, win10_policy: &DriverPolicy, win11_policy: &DriverPolicy) -> Self {
        
        let has_terminate_process = {
            let has_terminate = driver.imports.iter().any(|import| import == "ZwTerminateProcess");
            let has_lookup_open = driver.imports.iter().any(|import| 
                matches!(import.as_str(), "ZwOpenProcess" | "PsLookupProcessByProcessId"));
            
            has_terminate && has_lookup_open
        };
        
        let has_communication = driver.imports.iter()
            .any(|import| COMMUNICATION_IMPORTS.contains(&import.as_str()));
        
        let critical_imports: Vec<String> = driver.imports.iter()
            .filter(|import| DANGEROUS_IMPORTS.contains(&import.as_str()))
            .cloned()
            .collect();

        // Extract both file version and original filename
        let (file_version, original_filename) = VersionInfo::from_file(&driver.path)
            .map(|info| {
                let version = if info.file_version.trim().is_empty() { 
                    "Unknown".to_string() 
                } else { 
                    sanitize_version_string(&info.file_version) 
                };
                
                let orig_name = if info.original_filename.trim().is_empty() {
                    "Unknown".to_string()
                } else {
                    info.original_filename.clone()
                };
                
                (version, orig_name)
            })
            .unwrap_or_else(|_| ("Unknown".to_string(), "Unknown".to_string()));

        let (is_win10_blocked, win10_block_reason, win10_blocking_details) = 
            Self::check_policy(&driver.path, win10_policy, "Win10");

        let (is_win11_blocked, win11_block_reason, win11_blocking_details) = 
            Self::check_policy(&driver.path, win11_policy, "Win11");

        Self {
            name: driver.name.clone(),
            architecture: driver.architecture.clone(),
            path: driver.path.to_string_lossy().into_owned(),
            size: format_file_size(driver.size),
            file_version,
            original_filename,  // ADD THIS
            sha256: hash,
            critical_imports,
            is_loldriver,
            is_win10_blocked,
            win10_block_reason,
            win10_blocking_details,
            is_win11_blocked,
            win11_block_reason,
            win11_blocking_details,
            has_terminate_process,
            has_communication,
        }
    }

    fn check_policy(path: &Path, policy: &DriverPolicy, policy_name: &str) -> (bool, String, Option<BlockingDetails>) {
        match msft_block_policy(&path.to_string_lossy(), policy) {
            Ok(result) => (result.is_blocked, result.reason, result.blocking_details),
            Err(e) => {
                warn!("Failed to check {} policy for {}: {}", policy_name, path.display(), e);
                (false, format!("{} policy check failed", policy_name), None)
            }
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "architecture": self.architecture,
            "path": self.path,
            "size": self.size,
            "file_version": self.file_version,
            "original_filename": self.original_filename,  // ADD THIS
            "sha256": self.sha256,
            "critical_imports": self.critical_imports.join(", "),
            "is_loldriver": self.is_loldriver,
            "is_win10_blocked": self.is_win10_blocked,
            "win10_block_reason": self.win10_block_reason,
            "win10_blocking_details": self.win10_blocking_details,
            "is_win11_blocked": self.is_win11_blocked,
            "win11_block_reason": self.win11_block_reason,
            "win11_blocking_details": self.win11_blocking_details,
            "has_terminate_process": self.has_terminate_process,
            "has_communication": self.has_communication
        })
    }

    fn write_blocking_details(writer: &mut BufWriter<File>, details: &BlockingDetails, os_version: &str) -> std::io::Result<()> {
        writeln!(writer, "{} Detailed Blocking Information:", os_version)?;
        writeln!(writer, "  Rule Type: {}", details.rule_type)?;
        
        if let Some(rule) = &details.matched_rule {
            writeln!(writer, "  Matched Rule ID: {}", rule.id.as_deref().unwrap_or("unknown"))?;
            writeln!(writer, "  Rule Friendly Name: {}", rule.friendly_name.as_deref().unwrap_or("N/A"))?;
            if let Some(hash) = &rule.hash {
                writeln!(writer, "  Rule Hash: {}", hash)?;
            }
            if let Some(filename) = &rule.file_name {
                writeln!(writer, "  Rule Filename: {}", filename)?;
            }
            if let Some(min_ver) = &rule.minimum_file_version {
                writeln!(writer, "  Minimum Version: {}", min_ver)?;
            }
            if let Some(max_ver) = &rule.maximum_file_version {
                writeln!(writer, "  Maximum Version: {}", max_ver)?;
            }
        }
        
        if let Some(cert) = &details.matched_certificate {
            writeln!(writer, "  Blocked Certificate Subject: {}", cert.subject_name)?;
            writeln!(writer, "  Certificate TBS SHA1: {}", cert.tbs_sha1)?;
            writeln!(writer, "  Certificate TBS SHA256: {}", cert.tbs_sha256)?;
            writeln!(writer, "  Certificate Thumbprint: {}", cert.thumbprint)?;
        }
        
        if let Some(signer_id) = &details.blocked_signer_id {
            writeln!(writer, "  Blocked Signer ID: {}", signer_id)?;
        }
        if let Some(publisher) = &details.publisher_info {
            writeln!(writer, "  Publisher Info: {}", publisher)?;
        }
        writeln!(writer, "  Detailed Explanation: {}", details.detailed_explanation)?;
        
        Ok(())
    }
}

struct LolDriversChecker {
    hash_set: HashSet<String>,
}

impl LolDriversChecker {
    fn new(policy_dir: &str) -> Result<Self, Box<dyn Error>> {
        info!("Loading loldrivers list from policy directory: {}", policy_dir);
        let lol_drivers_path = Path::new(policy_dir).join("lol_drivers.json");
        let file_content = std::fs::read_to_string(&lol_drivers_path)
            .map_err(|e| format!("Failed to read lol_drivers.json from {}: {}", lol_drivers_path.display(), e))?;
        
        let drivers: Value = serde_json::from_str(&file_content)?;
        let mut hash_set = HashSet::new();
        
        if let Some(drivers_array) = drivers.as_array() {
            for driver in drivers_array {
                if let Some(samples) = driver["KnownVulnerableSamples"].as_array() {
                    for sample in samples {
                        if let Some(hash) = sample["SHA256"].as_str() {
                            hash_set.insert(hash.to_string());
                        }
                    }
                }
            }
        }
        
        info!("Successfully loaded loldrivers list with {} unique hashes", hash_set.len());
        Ok(LolDriversChecker { hash_set })
    }

    fn is_loldriver(&self, hash: &str) -> bool {
        self.hash_set.contains(hash)
    }
}

pub fn analyze_single_driver(driver_path: &str, output_dir: &str, policy_dir: &str, use_json: bool) -> Result<(), Box<dyn Error>> {
    let loldriver_checker = LolDriversChecker::new(policy_dir)?;
    
    info!("Loading Windows 10 driver policy from: {}", policy_dir);
    let win10_policy_path = Path::new(policy_dir).join("Win10_MicrosoftDriverBlockPolicy.json");
    let win10_policy = load_policy(&win10_policy_path.to_string_lossy())
        .map_err(|e| format!("Failed to load Win10 policy from {}: {}", win10_policy_path.display(), e))?;
    
    info!("Loading Windows 11 driver policy from: {}", policy_dir);
    let win11_policy_path = Path::new(policy_dir).join("Win11_MicrosoftDriverBlockPolicy.json");
    let win11_policy = load_policy(&win11_policy_path.to_string_lossy())
        .map_err(|e| format!("Failed to load Win11 policy from {}: {}", win11_policy_path.display(), e))?;
    
    std::fs::create_dir_all(&output_dir)?;

    let driver_file_path = Path::new(driver_path);
    if !driver_file_path.exists() {
        return Err(format!("Driver file does not exist: {}", driver_path).into());
    }

    info!("Analyzing driver: {}", driver_file_path.display());
    
    let driver = DriverInfo::new(&driver_file_path)
        .map_err(|e| format!("Failed to analyze driver {}: {}", driver_file_path.display(), e))?;
    
    let file_hash = calculate_file_hash(&driver.path)?;
    let is_loldriver = loldriver_checker.is_loldriver(&file_hash);
    let analysis = DriverAnalysis::from_driver_info(&driver, file_hash, is_loldriver, &win10_policy, &win11_policy);

    let driver_name = driver_file_path.file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_driver");
    
    let file_extension = if use_json { "json" } else { "txt" };
    let output_filename = format!("{}_analysis.{}", driver_name, file_extension);
    let output_path = Path::new(output_dir).join(output_filename);

    if use_json {
        let json_data = json!({
            "summary": {
                "driver_name": analysis.name,
                "is_loldriver": analysis.is_loldriver,
                "is_win10_blocked": analysis.is_win10_blocked,
                "is_win11_blocked": analysis.is_win11_blocked
            },
            "detailed_analysis": analysis.to_json()
        });
        let json_string = serde_json::to_string_pretty(&json_data)?;
        std::fs::write(&output_path, &json_string)?;
        
        // Print the JSON to console
        println!("{}", json_string);
        
    } else {
        let mut writer = BufWriter::new(File::create(&output_path)?);
        writeln!(writer, "=== DRIVER VULNERABILITY ANALYSIS REPORT ===")?;
        writeln!(writer, "")?;
        
        writeln!(writer, "BASIC INFORMATION:")?;
        writeln!(writer, "Driver Name: {} ({})", analysis.name, analysis.architecture)?;
        writeln!(writer, "Original Filename: {}", analysis.original_filename)?;
        writeln!(writer, "Path: {}", analysis.path)?;
        writeln!(writer, "Size: {}", analysis.size)?;
        writeln!(writer, "File Version: {}", analysis.file_version)?;
        writeln!(writer, "SHA256: {}", analysis.sha256)?;
        writeln!(writer, "")?;

        writeln!(writer, "SECURITY ANALYSIS:")?;
        writeln!(writer, "Listed on LolDrivers: {}", if analysis.is_loldriver { "YES - Known vulnerable driver" } else { "No" })?;
        writeln!(writer, "Has Critical Imports: {}", if !analysis.critical_imports.is_empty() { "YES" } else { "No" })?;
        writeln!(writer, "Has Terminate Process Capability: {}", if analysis.has_terminate_process { "YES" } else { "No" })?;
        writeln!(writer, "Has Communication Capability: {}", if analysis.has_communication { "YES" } else { "No" })?;
        writeln!(writer, "")?;

        writeln!(writer, "MICROSOFT BLOCKING POLICIES:")?;
        writeln!(writer, "Windows 10 Blocked: {} - {}", 
            if analysis.is_win10_blocked { "YES" } else { "No" }, 
            analysis.win10_block_reason)?;
        
        if let Some(win10_details) = &analysis.win10_blocking_details {
            DriverAnalysis::write_blocking_details(&mut writer, win10_details, "Windows 10")?;
        }
        
        writeln!(writer, "Windows 11 Blocked: {} - {}", 
            if analysis.is_win11_blocked { "YES" } else { "No" }, 
            analysis.win11_block_reason)?;
            
        if let Some(win11_details) = &analysis.win11_blocking_details {
            DriverAnalysis::write_blocking_details(&mut writer, win11_details, "Windows 11")?;
        }
        
        writeln!(writer, "")?;

        if !analysis.critical_imports.is_empty() {
            writeln!(writer, "CRITICAL IMPORTS DETECTED:")?;
            for import in &analysis.critical_imports {
                writeln!(writer, "  - {}", import)?;
            }
        }
    }
    
    info!("Analysis completed successfully!");
    info!("LOLDriver Status: {}", if analysis.is_loldriver { "Listed in LOLDrivers" } else { "Not in LOLDrivers" });
    info!("Win10 Blocked: {}", analysis.is_win10_blocked);
    info!("Win11 Blocked: {}", analysis.is_win11_blocked);
    info!("Results saved to: {}", output_path.display());

    Ok(())
}