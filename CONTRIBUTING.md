# Contributing to SecureMailScope

Thank you for your interest in contributing to SecureMailScope! This document provides guidelines for contributing to this project.

## 🔒 Security First

SecureMailScope is designed for sovereign defense infrastructure. All contributions **must** adhere to:

1. **Zero Decryption Principle** — Never attempt to decrypt, reassemble, or inspect email payload bodies.
2. **Air-Gapped Operation** — No external network calls, cloud APIs, or CDN dependencies.
3. **Zero Host Agents** — The framework is purely passive and agentless.

## 🚀 Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Set up your development environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## 📐 Code Standards

- **Python 3.12+** with strict type hints
- **Pydantic v2** for all data models
- Follow PEP 8 style guidelines
- Memory-efficient patterns (zero-copy where possible)
- All code must handle corrupted/malformed packets gracefully

## 📝 Pull Request Process

1. Ensure your code compiles and passes basic syntax checks
2. Update documentation if you change any APIs
3. Add unit tests for new functionality
4. Create a Pull Request with a clear description of changes

## 🐛 Reporting Issues

Please use GitHub Issues to report bugs. Include:
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Relevant log output

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.
