# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0.0](https://github.com/Madhur-Prakash/Auth/compare/v1.2.0...v2.0.0) - 14-01-2026

### Added
- **Full Data Encryption**
  - Implemented encryption for sensitive user data including email, phone number, and personal identifiers.
  - Ensured encryption is applied before persisting data to the database (data-at-rest protection).
- **Deterministic Hashing**
  - Introduced deterministic hashing for selected fields to enable secure equality checks.
  - Enabled safe lookups without exposing or storing plaintext values.
- **Security-First Architecture**
  - Added helper utilities for encryption, decryption, and hashing consistency.
  - Improved internal security workflows and data handling standards.

### Changed
- Refactored file structure and data access layers to support encrypted fields and deterministic hashing.
- Updated authentication, signup, and verification flows to work with encrypted and hashed data.
- Modified validation and lookup logic to rely on deterministic hashes instead of plaintext comparisons.
- Improved logging strategy to avoid accidental exposure of sensitive information.

### Fixed
- Potential security gaps related to plaintext data handling.
- Edge cases where sensitive data could appear in logs or error traces.

### Removed
- Plaintext storage of sensitive fields.
- Legacy lookup mechanisms that relied on raw, unencrypted data.

### Breaking Changes
- Plaintext search on sensitive fields is no longer supported.
- Existing databases require migration to encrypted and hashed formats.
- Any integrations relying on raw data access must be updated.

### Notes
- This release represents a **major security overhaul**.
- Data migration is required before deploying this version in production.
- Strongly recommended for environments requiring higher security and compliance readiness.

## [1.2.0](https://github.com/Madhur-Prakash/Auth/compare/v1.1.0...v1.2.0) - 10-10-2025

### Added
- **XSS Protection:**
  - Implemented input sanitization functions (`sanitize_input`) to prevent malicious script injections.
  - Enhanced form data and request body validation layers for safer user interactions.
- **Comprehensive Error Handling:**
  - Added centralized exception handling with descriptive HTTP response structures.
  - Improved validation feedback for better developer and API client debugging.

### Changed
- Refined password, email, and phone validation logic for stricter security compliance.
- Improved code quality by removing unused imports and redundant logic across modules.
- Updated security configurations for cookies, sessions, and rate-limiting to align with production standards.
- Ensured code adheres to **PEP8** and **secure coding best practices**.

### Fixed
- Minor inconsistencies in validation error messages.
- Occasional input parsing issues during form submissions.

### Removed
- Deprecated functions and unused imports that no longer align with the current architecture.

### Notes
- This release strengthens the overall **security posture** of the authentication system.
- The project is now more **resilient**, **maintainable**, and **ready for production deployment** with improved developer experience.


## [1.1.0](https://github.com/Madhur-Prakash/Auth/compare/v1.0.2...v1.1.0) - 17-08-2025
### Added
- **Complete Dockerization** of the authentication service for streamlined containerized deployment:
  - Added `Dockerfile` for building the auth service image.
  - Added `docker-compose.yml` to orchestrate dependent services including Redis, Kafka, and MongoDB.
- **Environment-based configuration** support for seamless switching between `local` and `docker` environments.
- **Persistent storage** setup for critical data:
  - MongoDB volumes ensure data persistence across container restarts.
- Automated dependency installation and build process inside Docker for consistent and faster environment setup.

### Changed
- Restructured project folder layout to optimize for containerized workflows and easier deployment.
- Adjusted service ports and Docker network bindings to avoid conflicts with local host services.
- Centralized configuration management via `.env` files to reduce hardcoding and improve environment flexibility.

### Fixed
- Resolved **Kafka connection timeout issues** by adding a startup wait script to ensure all dependencies are ready before service launch.

### Removed
- Unused scripts are now removed to streamline the project.

### Notes
- This release significantly improves **deployability, scalability, and reliability**, allowing the authentication service to run consistently across different environments.
- Developers can now rely on the Docker workflow for all setups, testing, and deployment.

## [1.0.2](https://github.com/Madhur-Prakash/Auth/compare/v1.0.1...v1.0.2) - 11-08-2025
### Changed
- Updated Readme for clear instructions.

## [1.0.1](https://github.com/Madhur-Prakash/Auth/compare/v1.0.0...v1.0.1) - 10-08-2025
### Changed
- Improved `.env` configuration guidance for setting up environment variables.

## [1.0.0](https://github.com/Madhur-Prakash/Auth/releases/tag/v1.0.0) - 07-07-2025

### Added
- FastAPI app setup with Docker and env configs
- JWT and Google OAuth2 authentication
- MongoDB integration with Pydantic models
- Redis support for caching, OTP, and Bloom filter
- Kafka producer and consumer integration
- Celery + Mailhog for async mail
- Complete HTML templates for auth flow
- Basic load testing with Locust
