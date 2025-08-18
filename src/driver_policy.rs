use std::fs;
use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use goblin::pe::PE;
use x509_parser::prelude::*;
use sha1::{Sha1, Digest};
use sha2::{Sha256, Digest as _};
use hex;
use serde::{Deserialize, Serialize};
use win32_version_info::VersionInfo;
use crate::utils::{sanitize_version_string};

const IGNORED_SIGNER_IDS: &[&str] = &[
    "ID_SIGNER_ASWARPOT_2", "ID_SIGNER_LDIAGIO_3", "ID_SIGNER_S_0015",
    "ID_SIGNER_S_0016", "ID_SIGNER_S_0050", "ID_SIGNER_S_0091",
    "ID_SIGNER_WINDOWS_3RD_PARTY_2012", "ID_SIGNER_WINDOWS_3RD_PARTY_2014",
];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertificateDetails {
    pub subject_name: String,
    pub thumbprint: String,
    pub tbs_sha1: String,
    pub tbs_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockingDetails {
    pub rule_type: String,
    pub matched_rule: Option<FileRule>,
    pub matched_certificate: Option<CertificateDetails>,
    pub blocked_signer_id: Option<String>,
    pub publisher_info: Option<String>,
    pub detailed_explanation: String,
}

#[derive(Debug)]
pub struct PolicyResult {
    pub is_blocked: bool,
    pub reason: String,
    pub matched_cert_tbs: Option<String>,
    pub matched_rules_count: Option<usize>,
    pub blocking_details: Option<BlockingDetails>,
}

#[derive(Debug)]
pub enum PolicyError {
    IoError(String),
    ParseError(String),
    PeError(String),
    NetworkError(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PolicyError::IoError(msg) => write!(f, "IO Error: {}", msg),
            PolicyError::ParseError(msg) => write!(f, "Parse Error: {}", msg),
            PolicyError::PeError(msg) => write!(f, "PE Error: {}", msg),
            PolicyError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
        }
    }
}

impl StdError for PolicyError {}

#[derive(Debug)]
struct CertInfo {
    subject_name: String,
    thumbprint: String,
    tbs_sha1: String,
    tbs_sha256: String,
}

impl CertInfo {
    fn to_certificate_details(&self) -> CertificateDetails {
        CertificateDetails {
            subject_name: self.subject_name.clone(),
            thumbprint: self.thumbprint.clone(),
            tbs_sha1: self.tbs_sha1.clone(),
            tbs_sha256: self.tbs_sha256.clone(),
        }
    }
}

#[derive(Debug)]
struct FileHashes {
    sha1: String,
    sha256: String,
    image_sha1: String,
    image_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct FileRule {
    pub id: Option<String>,
    pub friendly_name: Option<String>,
    pub file_name: Option<String>,
    pub minimum_file_version: Option<String>,
    pub maximum_file_version: Option<String>,
    pub hash: Option<String>,
    pub file_path: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct CertificateRoot {
    pub cert_type: Option<String>,
    pub value: Option<String>,
    pub common_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct CertificatePublisher {
    pub value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Signer {
    pub id: Option<String>,
    pub name: Option<String>,
    pub certificate_roots: Vec<CertificateRoot>,
    #[serde(default)]
    pub certificate_publishers: Vec<CertificatePublisher>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct DriverPolicy {
    pub file_rules: Vec<FileRule>,
    pub signers: Vec<Signer>,
}

#[derive(Debug)]
enum InternalPolicyResult {
    Blocked(String, Option<BlockingDetails>),
    Allowed(String),
}


pub fn load_policy(file_path: &str) -> Result<DriverPolicy, PolicyError> {
    let policy_content = fs::read_to_string(file_path)
        .map_err(|e| PolicyError::IoError(format!("Failed to read {}: {}", file_path, e)))?;
    
    serde_json::from_str(&policy_content)
        .map_err(|e| PolicyError::ParseError(format!("Failed to parse {}: {}", file_path, e)))
}

fn calculate_file_hashes(pe_path: &str) -> Result<FileHashes, PolicyError> {
    let pe_data = fs::read(pe_path)
        .map_err(|e| PolicyError::IoError(format!("Failed to read PE file: {}", e)))?;
    
    let pe = PE::parse(&pe_data)
        .map_err(|e| PolicyError::PeError(format!("Failed to parse PE: {}", e)))?;

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(&pe_data);
    let sha1 = hex::encode_upper(sha1_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&pe_data);
    let sha256 = hex::encode_upper(sha256_hasher.finalize());

    let (image_sha1, image_sha256) = calculate_authenticode_hashes(&pe_data, &pe)?;

    Ok(FileHashes { sha1, sha256, image_sha1, image_sha256 })
}

fn calculate_authenticode_hashes(pe_data: &[u8], pe: &PE) -> Result<(String, String), PolicyError> {
    let oh = pe.header.optional_header.as_ref()
        .ok_or_else(|| PolicyError::PeError("No optional header found".into()))?;

    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    let checksum_offset = pe_offset + 4 + 20 + 0x40;
    let security_offset = match pe.header.coff_header.machine {
        0x8664 => pe_offset + 4 + 20 + 0x70 + (4 * 8),
        _ => pe_offset + 4 + 20 + 0x60 + (4 * 8),
    };

    let cert_table_offset = oh.data_directories.get_certificate_table()
        .map(|cert_dir| if cert_dir.virtual_address > 0 { cert_dir.virtual_address as usize } else { pe_data.len() })
        .unwrap_or(pe_data.len());

    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    // Hash segments
    sha1_hasher.update(&pe_data[0..checksum_offset]);
    sha256_hasher.update(&pe_data[0..checksum_offset]);

    let after_checksum = checksum_offset + 4;
    let data_size = security_offset - after_checksum;
    sha1_hasher.update(&pe_data[after_checksum..after_checksum + data_size]);
    sha256_hasher.update(&pe_data[after_checksum..after_checksum + data_size]);

    let after_security = security_offset + 8;
    let final_data_size = cert_table_offset - after_security;
    sha1_hasher.update(&pe_data[after_security..after_security + final_data_size]);
    sha256_hasher.update(&pe_data[after_security..after_security + final_data_size]);

    // Add padding for 8-byte alignment
    let padding_size = final_data_size % 8;
    if padding_size != 0 {
        let zero_pad = vec![0u8; 8 - padding_size];
        sha1_hasher.update(&zero_pad);
        sha256_hasher.update(&zero_pad);
    }

    Ok((hex::encode_upper(sha1_hasher.finalize()), hex::encode_upper(sha256_hasher.finalize())))
}

fn parse_ver(s: &str) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (i, part) in s.split('.').take(4).enumerate() {
        if let Ok(v) = part.parse::<u32>() { 
            out[i] = v; 
        }
    }
    out
}

fn ver_in_range(ver: &str, min: Option<&str>, max: Option<&str>) -> bool {
    let v = parse_ver(ver);
    if let Some(m) = min { if v < parse_ver(m) { return false; } }
    if let Some(x) = max { if v > parse_ver(x) { return false; } }
    true
}

fn parse_pe_certificates(pe_path: &str) -> Result<Vec<CertInfo>, PolicyError> {
    let pe_data = fs::read(pe_path)
        .map_err(|e| PolicyError::IoError(format!("Failed to read PE file: {}", e)))?;
    
    let pe = PE::parse(&pe_data)
        .map_err(|e| PolicyError::PeError(format!("Failed to parse PE: {}", e)))?;

    let mut certificates = Vec::new();

    if let Some(oh) = &pe.header.optional_header {
        if let Some(cert_dir) = oh.data_directories.get_certificate_table() {
            let cert_offset = cert_dir.virtual_address as usize;
            let cert_size = cert_dir.size as usize;

            if cert_offset > 0 && cert_size > 0 && cert_offset + cert_size <= pe_data.len() {
                let cert_data = &pe_data[cert_offset..cert_offset + cert_size];
                certificates = parse_certificate_data(cert_data)?;
            }
        }
    }

    Ok(certificates)
}

fn parse_certificate_data(cert_data: &[u8]) -> Result<Vec<CertInfo>, PolicyError> {
    let mut certificates = Vec::new();
    let mut offset = 0;

    while offset + 8 <= cert_data.len() {
        let length = u32::from_le_bytes([
            cert_data[offset], cert_data[offset + 1], cert_data[offset + 2], cert_data[offset + 3]
        ]) as usize;

        let cert_type = u16::from_le_bytes([cert_data[offset + 6], cert_data[offset + 7]]);

        if length < 8 || offset + length > cert_data.len() { 
            break; 
        }

        if cert_type == 0x0002 {
            let pkcs7_data = &cert_data[offset + 8..offset + length];
            if let Ok(mut certs) = parse_pkcs7_certificates(pkcs7_data) {
                certificates.append(&mut certs);
            }
        }

        offset += (length + 7) & !7; // Aligned length
    }

    Ok(certificates)
}

fn parse_pkcs7_certificates(pkcs7_data: &[u8]) -> Result<Vec<CertInfo>, PolicyError> {
    let mut certificates = Vec::new();
    let mut offset = 0;

    while offset < pkcs7_data.len().saturating_sub(4) {
        if pkcs7_data[offset] == 0x30 {
            let mut cert_len = 0usize;
            let mut len_offset = offset + 1;

            if len_offset >= pkcs7_data.len() {
                offset += 1;
                continue;
            }

            let first_len_byte = pkcs7_data[len_offset];
            if first_len_byte & 0x80 == 0 {
                cert_len = first_len_byte as usize;
                len_offset += 1;
            } else {
                let num_octets = (first_len_byte & 0x7f) as usize;
                if num_octets == 0 || num_octets > 4 || len_offset + num_octets >= pkcs7_data.len() {
                    offset += 1;
                    continue;
                }
                len_offset += 1;
                for i in 0..num_octets {
                    if len_offset + i >= pkcs7_data.len() { break; }
                    cert_len = (cert_len << 8) | pkcs7_data[len_offset + i] as usize;
                }
                len_offset += num_octets;
            }

            let total_cert_size = len_offset - offset + cert_len;
            if offset + total_cert_size <= pkcs7_data.len() && cert_len > 0 && cert_len < 0x100000 {
                let cert_data = &pkcs7_data[offset..offset + total_cert_size];
                if let Ok((_, cert)) = X509Certificate::from_der(cert_data) {
                    if let Ok(cert_info) = extract_cert_info(&cert, cert_data) {
                        certificates.push(cert_info);
                    }
                    offset += total_cert_size;
                    continue;
                }
            }
        }
        offset += 1;
    }

    Ok(certificates)
}

fn extract_cert_info(cert: &X509Certificate, cert_der_bytes: &[u8]) -> Result<CertInfo, PolicyError> {
    let subject_name = cert.subject().to_string();

    let mut hasher = Sha1::new();
    hasher.update(cert_der_bytes);
    let thumbprint = hex::encode_upper(hasher.finalize());

    let tbs_der = cert.tbs_certificate.as_ref();
    let mut tbs_sha1_hasher = Sha1::new();
    tbs_sha1_hasher.update(tbs_der);
    let tbs_sha1 = hex::encode_upper(tbs_sha1_hasher.finalize());

    let mut tbs_sha256_hasher = Sha256::new();
    tbs_sha256_hasher.update(tbs_der);
    let tbs_sha256 = hex::encode_upper(tbs_sha256_hasher.finalize());

    Ok(CertInfo { subject_name, thumbprint, tbs_sha1, tbs_sha256 })
}

fn check_driver_against_policy(
    file_hashes: &FileHashes,
    certs: &[CertInfo],
    policy: &DriverPolicy,
    original_filename: Option<&str>,
    file_version: Option<&str>,
) -> InternalPolicyResult {
    let norm_upper = |s: &str| s.trim().to_uppercase();

    // Hash-based deny rules (highest priority)
    let mut hash_rule_map = std::collections::HashMap::new();
    for rule in &policy.file_rules {
        if let (Some(action), Some(hash)) = (&rule.action, &rule.hash) {
            if action.eq_ignore_ascii_case("deny") {
                hash_rule_map.insert(norm_upper(hash), rule.clone());
            }
        }
    }
    
    for (hash, kind) in [
        (&file_hashes.sha1, "file SHA-1"),
        (&file_hashes.sha256, "file SHA-256"),
        (&file_hashes.image_sha256, "image SHA-256"),
    ] {
        if let Some(matched_rule) = hash_rule_map.get(&norm_upper(hash)) {
            let rule_id = matched_rule.id.as_deref().unwrap_or("unknown");
            let msg = format!("Hash explicitly blocked ({}) - RuleID: {}", kind, rule_id);

            let blocking_details = BlockingDetails {
                rule_type: "hash".to_string(),
                matched_rule: Some(matched_rule.clone()),
                matched_certificate: None,
                blocked_signer_id: None,
                publisher_info: None,
                detailed_explanation: format!(
                    "Driver blocked by hash-based rule.\nHash Type: {}\nMatched Hash: {}\nRule ID: {}\nRule Details: {:?}",
                    kind, hash, rule_id, matched_rule
                ),
            };

            return InternalPolicyResult::Blocked(msg, Some(blocking_details));
        }
    }
    
    // Filename + Version deny rules
    if let (Some(ofn), Some(ver)) = (original_filename, file_version) {
        let ofn_up = norm_upper(ofn);
        let mut matching_rule: Option<FileRule> = None;
        let mut match_count = 0;

        for rule in &policy.file_rules {
            if rule.action.as_ref().map_or(false, |a| a.eq_ignore_ascii_case("deny")) 
                && rule.file_name.as_ref().map_or(false, |f| norm_upper(f) == ofn_up) {
                
                let min_v = rule.minimum_file_version.as_deref();
                let max_v = rule.maximum_file_version.as_deref();
                
                if (min_v.is_some() || max_v.is_some()) && ver_in_range(ver, min_v, max_v) {
                    match_count += 1;
                    if matching_rule.is_none() {
                        matching_rule = Some(rule.clone());
                    }
                }
            }
        }

        if let Some(rule) = matching_rule {
            let rule_id = rule.id.as_deref().unwrap_or("unknown");
            let reason = format!("File-version rule blocked: {} v{} - RuleID: {} (matched {} rules)", 
                ofn, ver, rule_id, match_count);

            let blocking_details = BlockingDetails {
                rule_type: "version".to_string(),
                matched_rule: Some(rule.clone()),
                matched_certificate: None,
                blocked_signer_id: None,
                publisher_info: None,
                detailed_explanation: format!(
                    "Driver blocked by file version rule.\nFilename: {}\nVersion: {}\nRule ID: {}\nMatched Rules: {}",
                    ofn, ver, rule_id, match_count
                ),
            };

            return InternalPolicyResult::Blocked(reason, Some(blocking_details));
        }
    }

    // Signer-based deny rules
    if !certs.is_empty() {
        let full_cert_chain = certs.iter()
            .map(|cert| format!("SUBJECT:{} THUMBPRINT:{} TBSSHA1:{} TBSSHA256:{}", 
                cert.subject_name, cert.thumbprint, cert.tbs_sha1, cert.tbs_sha256))
            .collect::<Vec<String>>()
            .join(" | ");

        for cert in certs {
            let tbs1 = norm_upper(&cert.tbs_sha1);
            let tbs256 = norm_upper(&cert.tbs_sha256);

            for signer in &policy.signers {
                if let Some(id) = &signer.id {
                    if IGNORED_SIGNER_IDS.contains(&id.as_str()) {
                        continue;
                    }
                }

                let denied_tbs: Vec<String> = signer.certificate_roots.iter()
                    .filter_map(|r| r.value.as_ref())
                    .map(|v| norm_upper(v))
                    .collect();

                if !denied_tbs.is_empty() && (denied_tbs.contains(&tbs1) || denied_tbs.contains(&tbs256)) {
                    for pub_entry in &signer.certificate_publishers {
                        if let Some(pub_val) = &pub_entry.value {
                            if full_cert_chain.to_uppercase().contains(&pub_val.to_uppercase()) {
                                let matched_tbs = format!("{}...", &cert.tbs_sha1[..16]);
                                let mut reason = format!("Certificate blocked (TBS: {})", matched_tbs);
                                
                                if let Some(rule_id) = &signer.id {
                                    reason.push_str(&format!(" - RuleID: {}", rule_id));
                                }
                                reason.push_str(&format!(" CertPublisher: {}", pub_val));

                                let blocking_details = BlockingDetails {
                                    rule_type: "certificate".to_string(),
                                    matched_rule: None,
                                    matched_certificate: Some(cert.to_certificate_details()),
                                    blocked_signer_id: signer.id.clone(),
                                    publisher_info: Some(pub_val.clone()),
                                    detailed_explanation: format!(
                                        "Driver blocked by certificate-based rule.\nCertificate Subject: {}\nTBS SHA1: {}\nTBS SHA256: {}\nThumbprint: {}\nSigner Rule ID: {}\nPublisher: {}",
                                        cert.subject_name, cert.tbs_sha1, cert.tbs_sha256, cert.thumbprint,
                                        signer.id.as_deref().unwrap_or("unknown"), pub_val
                                    ),
                                };
                                
                                return InternalPolicyResult::Blocked(reason, Some(blocking_details));
                            }
                        }
                    }
                }
            }
        }

        return InternalPolicyResult::Allowed("Signed driver not blocked".to_string());
    }

    // Unsigned drivers are blocked
    let blocking_details = BlockingDetails {
        rule_type: "unsigned".to_string(),
        matched_rule: None,
        matched_certificate: None,
        blocked_signer_id: None,
        publisher_info: None,
        detailed_explanation: "Driver blocked because it is unsigned.\nDriver has no digital signature certificates.\nUnsigned drivers are blocked by Microsoft policies.".to_string(),
    };

    InternalPolicyResult::Blocked("Unsigned driver".to_string(), Some(blocking_details))
}


pub fn msft_block_policy(pe_path: &str, policy: &DriverPolicy) -> Result<PolicyResult, PolicyError> {
    let file_hashes = calculate_file_hashes(pe_path)?;
    let certs = parse_pe_certificates(pe_path)?;

    let (orig_filename_opt, file_version_opt) = VersionInfo::from_file(pe_path)
        .map(|info| (
            Some(info.original_filename), 
            Some(sanitize_version_string(&info.file_version))
        ))
        .unwrap_or((None, None));

    let result = check_driver_against_policy(
        &file_hashes,
        &certs,
        policy,
        orig_filename_opt.as_deref(),
        file_version_opt.as_deref(),
    );

    match result {
        InternalPolicyResult::Blocked(reason, blocking_details) => {
            Ok(PolicyResult {
                is_blocked: true,
                reason,
                matched_cert_tbs: None,
                matched_rules_count: None,
                blocking_details,
            })
        }
        InternalPolicyResult::Allowed(reason) => {
            Ok(PolicyResult {
                is_blocked: false,
                reason,
                matched_cert_tbs: None,
                matched_rules_count: None,
                blocking_details: None,
            })
        }
    }
}