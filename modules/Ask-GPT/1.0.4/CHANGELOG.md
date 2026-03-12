# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-07-05

### Fixed
- Updated PowerShell version requirement from 5.1 to 7.0 to accurately reflect compatibility
- Improved module searchability on PowerShell Gallery with additional tags
- Enhanced module metadata for better discoverability

## [1.0.0] - 2025-06-30

### Added
- Initial release of Ask-GPT PowerShell module
- Core functionality for interacting with OpenAI GPT models
- Streaming response support
- Conversation history management
- Auto model detection
- ANSI escape sequence support for terminal formatting
- Temperature control for response randomness
- Pipeline support for PowerShell integration
- Comprehensive parameter validation
- `gpt` alias for easy command access

### Features
- Support for multiple OpenAI models with auto-detection
- Environment variable configuration (OPENAI_PERSONAL_API_KEY, OPENAI_API_KEY)
- Hyperlink support in terminal output
- Response timing display
- Clear history functionality
- Verbose logging for debugging

### Documentation
- Complete module manifest with metadata
- Comprehensive help documentation
- Installation and usage examples
- API key setup instructions
- Troubleshooting guide
- Contributing guidelines

## [Unreleased]

### Planned
- PowerShell Gallery publication
- Pester tests for robust testing
- Additional model parameters
- Configuration file support
- Plugin architecture for extensions
