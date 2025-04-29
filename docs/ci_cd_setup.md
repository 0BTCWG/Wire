# CI/CD Setup for 0BTC Wire

This document describes the Continuous Integration and Continuous Deployment (CI/CD) setup for the 0BTC Wire project.

## Overview

The CI/CD pipeline is implemented using GitHub Actions and automates the following processes:

1. **Building and testing** the project on each push and pull request
2. **Building the WASM package** for browser integration
3. **Creating releases** when version tags are pushed
4. **Running code quality checks** including formatting and linting

## Workflow Configuration

The CI/CD workflow is defined in `.github/workflows/rust.yml` and consists of three main jobs:

### 1. Build and Test

This job runs on every push to the main branch and on every pull request. It performs the following tasks:

- Sets up the Rust nightly toolchain
- Caches dependencies to speed up builds
- Checks code formatting with `cargo fmt`
- Lints the code with `cargo clippy`
- Builds the project
- Runs all tests
- Builds examples

### 2. WASM Build

This job builds the WebAssembly package for browser integration:

- Sets up the Rust nightly toolchain with WASM target
- Installs wasm-pack
- Builds the WASM package
- Uploads the WASM artifacts for use in the release job

### 3. Release

This job runs only when a tag starting with 'v' is pushed (e.g., v1.0.0). It performs the following tasks:

- Downloads the WASM artifacts from the WASM build job
- Builds release binaries
- Creates a release archive containing:
  - The compiled binary
  - Examples
  - Documentation
  - README
- Creates a GitHub Release
- Uploads the release archives (tar.gz and zip) and WASM package as release assets

## Using the CI/CD Pipeline

### For Development

1. Push your changes to a branch and create a pull request to the main branch
2. The CI/CD pipeline will automatically build and test your changes
3. Check the GitHub Actions tab for build status and test results
4. Address any issues reported by the CI/CD pipeline

### For Releases

1. Update the version number in `Cargo.toml`
2. Commit the changes
3. Create and push a tag with the version number:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
4. The CI/CD pipeline will automatically create a release with the compiled binary and WASM package

## Customizing the CI/CD Pipeline

To customize the CI/CD pipeline, edit the `.github/workflows/rust.yml` file. Some common customizations include:

- Adding additional test commands
- Configuring different build targets
- Adding deployment steps for specific platforms
- Integrating with code coverage tools

## Troubleshooting

If the CI/CD pipeline fails, check the following:

1. **Build Failures**: Ensure that the code builds locally with `cargo build`
2. **Test Failures**: Run tests locally with `cargo test` to reproduce and fix issues
3. **Formatting Issues**: Run `cargo fmt --all -- --check` to identify formatting problems
4. **Linting Issues**: Run `cargo clippy -- -D warnings` to identify linting issues

## GitHub Actions Secrets

The CI/CD pipeline uses the following GitHub secrets:

- `GITHUB_TOKEN`: Automatically provided by GitHub, used for creating releases and uploading assets

## Release Versioning

We follow Semantic Versioning (SemVer) for releases:

- **Major version** (X.0.0): Incompatible API changes
- **Minor version** (0.X.0): Backwards-compatible functionality additions
- **Patch version** (0.0.X): Backwards-compatible bug fixes

## Continuous Deployment

The current setup focuses on Continuous Integration and building release artifacts. To add Continuous Deployment:

1. Add deployment jobs to the workflow
2. Configure deployment targets (e.g., AWS, Azure, GCP)
3. Set up appropriate secrets for deployment authentication

## Future Improvements

Planned improvements to the CI/CD pipeline include:

1. **Cross-platform builds** for Windows, macOS, and Linux
2. **Automated benchmarking** to track performance changes
3. **Code coverage reporting** to ensure test coverage
4. **Dependency scanning** for security vulnerabilities
