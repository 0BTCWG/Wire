# 0BTC Wire Installation Guide

This guide provides detailed instructions for installing and setting up the 0BTC Wire zero-knowledge proof system on different platforms.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Linux Installation](#linux-installation)
3. [macOS Installation](#macos-installation)
4. [Windows Installation](#windows-installation)
5. [WASM Installation](#wasm-installation)
6. [Building from Source](#building-from-source)
7. [Troubleshooting](#troubleshooting)
8. [Generating Test Vectors](#generating-test-vectors)

## Prerequisites

Before installing 0BTC Wire, ensure you have the following prerequisites:

- Rust toolchain (nightly version recommended)
- OpenSSL development libraries
- Node.js and npm (for WASM integration)
- wasm-pack (for building WASM modules)
- At least 8GB RAM for standard operations
- At least 16GB RAM for generating test vectors and benchmarks

## Linux Installation

### Using Pre-built Binaries

1. Download the latest release package:

```bash
curl -LO https://github.com/0BTC/Wire/releases/latest/download/wire-linux-x86_64.tar.gz
```

2. Extract the package:

```bash
tar -xzf wire-linux-x86_64.tar.gz -C /usr/local
```

3. Add the binary to your PATH:

```bash
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

4. Verify the installation:

```bash
wire --version
```

### Installing Dependencies for Building from Source

If you plan to build from source, install the required dependencies:

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev pkg-config curl
```

#### Fedora/RHEL/CentOS

```bash
sudo dnf install -y gcc gcc-c++ make openssl-devel pkgconfig curl
```

#### Arch Linux

```bash
sudo pacman -S base-devel openssl pkg-config curl
```

## macOS Installation

### Using Pre-built Binaries

1. Download the latest release package:

```bash
curl -LO https://github.com/0BTC/Wire/releases/latest/download/wire-macos-x86_64.tar.gz
```

2. Extract the package:

```bash
tar -xzf wire-macos-x86_64.tar.gz -C /usr/local
```

3. Add the binary to your PATH:

```bash
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.zshrc
source ~/.zshrc
```

4. Verify the installation:

```bash
wire --version
```

### Installing Dependencies for Building from Source

If you plan to build from source, install the required dependencies:

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install openssl@3 pkg-config

# Set OpenSSL environment variables
echo 'export OPENSSL_DIR=$(brew --prefix openssl@3)' >> ~/.zshrc
source ~/.zshrc
```

## Windows Installation

### Using Pre-built Binaries

1. Download the latest release package from the [GitHub Releases page](https://github.com/0BTC/Wire/releases/latest/download/wire-windows-x86_64.zip).

2. Extract the ZIP file to a location of your choice (e.g., `C:\Program Files\Wire`).

3. Add the binary location to your PATH:
   - Right-click on "This PC" or "My Computer" and select "Properties"
   - Click on "Advanced system settings"
   - Click on "Environment Variables"
   - Under "System variables", find the "Path" variable, select it, and click "Edit"
   - Click "New" and add the path to the Wire binary (e.g., `C:\Program Files\Wire\bin`)
   - Click "OK" to close all dialogs

4. Verify the installation by opening a new Command Prompt and running:

```cmd
wire --version
```

### Installing Dependencies for Building from Source

If you plan to build from source, install the required dependencies:

1. Install Visual Studio Build Tools:
   - Download and install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - During installation, select "C++ build tools" and ensure the following components are selected:
     - MSVC v142 - VS 2019 C++ x64/x86 build tools
     - Windows 10 SDK
     - C++ CMake tools for Windows

2. Install OpenSSL:
   - Download and install [vcpkg](https://github.com/microsoft/vcpkg)
   - Install OpenSSL:
     ```cmd
     vcpkg install openssl:x64-windows
     ```
   - Set environment variables:
     ```cmd
     setx OPENSSL_DIR "C:\vcpkg\installed\x64-windows"
     setx OPENSSL_LIB_DIR "C:\vcpkg\installed\x64-windows\lib"
     setx OPENSSL_INCLUDE_DIR "C:\vcpkg\installed\x64-windows\include"
     ```

## WASM Installation

### Using Pre-built WASM Package

1. Download the latest WASM package:

```bash
curl -LO https://github.com/0BTC/Wire/releases/latest/download/wire-wasm.zip
```

2. Extract the package:

```bash
unzip wire-wasm.zip -d wire-wasm
```

3. Include the WASM module in your web project:

```html
<script type="module">
  import * as wire from './wire-wasm/wire.js';

  async function init() {
    await wire.default();
    console.log("Wire WASM module initialized");
  }

  init();
</script>
```

### Installing in an npm Project

If you're using npm, you can install the WASM package locally:

```bash
# Extract the WASM package
unzip wire-wasm.zip -d wire-wasm

# Install it as a local dependency
npm install --save ./wire-wasm
```

Then import it in your JavaScript:

```javascript
import * as wire from 'wire';

async function init() {
  await wire.default();
  console.log("Wire WASM module initialized");
}

init();
```

## Building from Source

If you prefer to build 0BTC Wire from source, follow these steps:

1. Install Rust (nightly toolchain):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
```

2. Clone the repository:

```bash
git clone https://github.com/0BTC/Wire.git
cd Wire
```

3. Build the project:

```bash
cargo build --release
```

4. Install the CLI globally (optional):

```bash
cargo install --path .
```

5. Build the WASM package (optional):

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build the WASM package
wasm-pack build --target web --out-dir pkg
```

## Troubleshooting

### Common Issues and Solutions

#### Rust Toolchain Issues

If you encounter issues with the Rust toolchain:

```bash
rustup update
rustup default nightly
```

#### OpenSSL Issues on Linux

If you encounter OpenSSL-related errors:

```bash
sudo apt-get install -y libssl-dev pkg-config
```

#### OpenSSL Issues on macOS

If you encounter OpenSSL-related errors on macOS:

```bash
brew install openssl@3
export OPENSSL_DIR=$(brew --prefix openssl@3)
```

#### OpenSSL Issues on Windows

If you encounter OpenSSL-related errors on Windows:

```cmd
vcpkg install openssl:x64-windows
setx OPENSSL_DIR "C:\vcpkg\installed\x64-windows"
setx OPENSSL_LIB_DIR "C:\vcpkg\installed\x64-windows\lib"
setx OPENSSL_INCLUDE_DIR "C:\vcpkg\installed\x64-windows\include"
```

#### WASM Build Issues

If you encounter issues building the WASM package:

```bash
# Update wasm-pack
cargo install wasm-pack --force

# Ensure you have the wasm32 target
rustup target add wasm32-unknown-unknown
```

### Getting Help

If you encounter issues not covered in this guide:

1. Check the [GitHub Issues](https://github.com/0BTC/Wire/issues) for similar problems
2. Run with verbose logging enabled:
   ```bash
   RUST_LOG=debug wire --version
   ```
3. Open a new issue with detailed information about your problem

## Generating Test Vectors

To generate test vectors for auditing, run the following command:

```bash
cargo run --release --bin generate_audit_test_vectors -- --output-dir ./test_vectors
```

This will generate test vectors for the 0BTC Wire protocol and save them to the specified output directory.

For more options and customization, you can run:

```bash
cargo run --release --bin generate_audit_test_vectors -- --help
```

Note: Generating test vectors requires at least 16GB of RAM. If you have less than 16GB of RAM, you may need to increase the amount of RAM available to your system or use a cloud-based service to generate the test vectors.
