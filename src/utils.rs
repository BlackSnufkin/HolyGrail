use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

pub const DANGEROUS_IMPORTS: &[&str] = &[
    // Physical / MDL primitives
    "MmGetPhysicalAddress",
    "MmMapIoSpace", "MmMapIoSpaceEx", "MmUnmapIoSpace",
    "MmAllocatePagesForMdl", "MmAllocatePagesForMdlEx",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPagesWithReservedMapping",
    "IoAllocateMdl", "IoFreeMdl",
    "MmCopyMemory",
    "MmCopyVirtualMemory",

    // Section / VM mapping & cross-proc R/W
    "ZwOpenSection",
    "ZwMapViewOfSection", "ZwUnmapViewOfSection",
    "ZwOpenProcess",
    "ZwReadVirtualMemory", "ZwWriteVirtualMemory",
    "KeStackAttachProcess",

    // Kill primitive
    "ZwTerminateProcess", "PsLookupProcessByProcessId",

];
pub const COMMUNICATION_IMPORTS: &[&str] = &[
    "IoCreateDevice",
    "IoCreateSymbolicLink", "IoDeleteSymbolicLink", 
    "IoDeleteDevice",
    "IoGetDeviceObjectPointer", "IoAttachDevice",
    "IofCompleteRequest",
    "FltRegisterFilter", "FltCreateCommunicationPort",
];


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DriverInfo {
    pub path: PathBuf,
    pub size: u64,
    pub name: String,
    pub imports: Vec<String>,
    pub architecture: String,
}

impl DriverInfo {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let file_data = std::fs::read(path)?;
        
        let (architecture, imports) = match PE::parse(&file_data) {
            Ok(pe) => {
                // Normal case - goblin worked
                let arch = match pe.header.coff_header.machine {
                    goblin::pe::header::COFF_MACHINE_X86 => "x32",
                    goblin::pe::header::COFF_MACHINE_X86_64 => "x64", 
                    _ => "Unknown",
                };
                
                let imports: Vec<String> = pe.imports.iter()
                    .map(|import| import.name.to_string())
                    .collect();
                    
                (arch.to_string(), imports)
            },
            Err(e) if e.to_string().contains("Cannot find name from rva") => {
                // Goblin failed on RVA - scan for function names as strings
                let arch = Self::get_arch_from_headers(&file_data);
                let imports = Self::scan_for_target_functions(&file_data);
                (arch, imports)
            },

            Err(_) => {
                ("Unknown".to_string(), Vec::new())
            }
        };

        let size = fs::metadata(path)?.len();
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;

        Ok(Self {
            path: path.to_path_buf(),
            size,
            name,
            imports,
            architecture,
        })
    }

    fn get_arch_from_headers(file_data: &[u8]) -> String {
        if file_data.len() < 64 || &file_data[0..2] != b"MZ" {
            return "Unknown".to_string();
        }

        let pe_offset = u32::from_le_bytes([
            file_data[60], file_data[61], file_data[62], file_data[63]
        ]) as usize;

        if pe_offset + 6 > file_data.len() {
            return "Unknown".to_string();
        }

        let machine = u16::from_le_bytes([
            file_data[pe_offset + 4], file_data[pe_offset + 5]
        ]);

        match machine {
            0x014c => "x32".to_string(),
            0x8664 => "x64".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    fn scan_for_target_functions(file_data: &[u8]) -> Vec<String> {
        let mut found_imports = Vec::new();
        let file_str = String::from_utf8_lossy(file_data);
        
        // Just scan for the target functions we care about
        for &target_import in DANGEROUS_IMPORTS {
            if file_str.contains(target_import) {
                found_imports.push(target_import.to_string());
            }
        }

        found_imports
    }
}

pub fn calculate_file_hash(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536]; // 64KB buffer
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[("GB", 1_073_741_824), ("MB", 1_048_576), ("KB", 1024)];
    
    for &(unit, threshold) in UNITS {
        if bytes >= threshold {
            return format!("{:.2}{}", bytes as f64 / threshold as f64, unit);
        }
    }
    format!("{}B", bytes)
}

pub fn sanitize_version_string(raw_version: &str) -> String {
    raw_version
        .split(|c: char| c == ',' || c == '.' || c.is_whitespace())
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}