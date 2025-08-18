# HolyGrail

A BYOVD hunter for finding the HolyGrail driver - Windows drivers suitable for BYOVD.

## Install

```bash
git clone <repository-url>
cd HolyGrail
cargo build --release
```

## Quick start

```bash
HolyGrail.exe -d "C:\path\to\driver.sys"
```

Add JSON output, custom output dir, and policy dir if you need:

```bash
HolyGrail.exe -d "C:\path\to\driver.sys" -o ".\out" -p ".\Policies" --json
```

## CLI

```
Usage: HolyGrail.exe [OPTIONS] --driver <DRIVER_FILE>

Options:
  -d, --driver <DRIVER_FILE>         Path to the driver file (.sys/.dll) to analyze
  -o, --output <OUTPUT_DIRECTORY>    Output directory for analysis results [default: .\Analysis]
  -p, --policies <POLICY_DIRECTORY>  Path to directory containing policy files [default: Policies]
  -j, --json                         Output results in JSON instead of text
  -v, --verbose                      Enable verbose logging
  -h, --help                         Print help
  -V, --version                      Print version
```

## What it checks

- **Kernel imports** commonly used in BYOVD chains (memory/MDL, section/VM mapping, cross-proc R/W, process control, device I/O).
- **Block policies**: compares the driver against Microsoft’s Windows 10/11 Driver Block Policy (File Version, AuthCode Hash, Certificate).
- **LoLDrivers**: flags if the driver appears there.
- **Basic comms hints**: device interfaces that suggest an easy user-mode bridge.

## Policy files

Place these in the `Policies` directory (or point `-p` to where they live):

```
Policies/
├── lol_drivers.json
├── Win10_MicrosoftDriverBlockPolicy.json
└── Win11_MicrosoftDriverBlockPolicy.json
```

## What counts as a “HolyGrail” driver

- Has the **right imports** for your technique (e.g., cross-process R/W, section mapping, termination).
- **Not on LoLDrivers** (less attention from defenders).
- **Not blocked** on Windows 10 and Windows 11 (loads without policy issues).
- **Has a comms path** (IOCTLs/device objects) for easy control.

## Use cases

- **Red teams**: surface legitimate, loadable drivers with the primitives you need.
- **Researchers**: map new candidates and study real-world attack surfaces.
- **Defenders (optional)**: audit your fleet for BYOVD risk.
