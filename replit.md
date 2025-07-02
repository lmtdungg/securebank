# SecureBank Pro - Banking Security Game

## Overview

SecureBank Pro is an educational cybersecurity simulation game that teaches banking security concepts through interactive gameplay. Players take on the role of a bank security administrator, performing encryption, authentication, and integrity checks on financial transactions. The application combines modern cryptographic algorithms (AES, RSA, SHA) with engaging gameplay mechanics to create an immersive learning experience.

## System Architecture

### Frontend Architecture
- **Dual Interface Design**: Both desktop (PySide6) and web (HTML/CSS/JavaScript) implementations
- **Modern UI Framework**: PySide6 (Qt for Python) for rich desktop experience with native widgets
- **Web Interface**: Self-contained HTML file with embedded CSS/JavaScript for browser accessibility
- **Animated Components**: Custom particle systems, gradient animations, and smooth transitions
- **Responsive Design**: Adaptive layouts supporting various screen sizes and devices

### Backend Architecture  
- **Game Engine**: Python-based core logic handling player progression, challenges, and scoring systems
- **Modular Design**: Separated concerns with dedicated modules for cryptography, UI, and game logic
- **Event-Driven Architecture**: Qt signals/slots for desktop UI, DOM events for web interface
- **State Management**: In-memory game state with automatic save/load functionality

### Security Implementation
- **Multi-Layer Encryption**: AES-256 for symmetric encryption, RSA for asymmetric operations
- **Hash Functions**: SHA-256 for data integrity verification and transaction fingerprinting
- **OTP System**: 6-digit one-time password generation for two-factor authentication simulation
- **Input Validation**: Comprehensive sanitization and error handling for all user inputs

## Key Components

### 1. Desktop Application (`main.py`)
- **Purpose**: Native desktop game client with full feature set
- **Architecture**: MVC pattern with Qt widgets as views, Python classes as controllers
- **Key Features**: Advanced animations, upgrade system, progress tracking
- **Rationale**: Chosen for rich UI capabilities and cross-platform compatibility

### 2. Cryptographic Module (`crypto_utils.py`)
- **Purpose**: Secure implementation of encryption algorithms used in gameplay
- **Implementation**: 
  - AES encryption in CBC mode with random IV generation
  - URL-safe Base64 encoding for data transmission
  - Comprehensive error handling and input validation
- **Security Considerations**: Proper padding, IV management, and key derivation
- **Rationale**: Isolated crypto logic for security auditing and modularity

### 3. Web Interface (`securebank_pro.html`)
- **Purpose**: Standalone web version for broader accessibility
- **Architecture**: Single-file application with embedded CSS/JavaScript
- **Features**: Banking-themed UI, particle animations, responsive design
- **Limitations**: JavaScript crypto implementation (educational purposes only)
- **Rationale**: Zero-dependency deployment for educational environments

### 4. Game Content Files
- **Requirements Documentation**: Vietnamese specification outlining game mechanics
- **Setup Guides**: VS Code integration and deployment instructions
- **Educational Materials**: Quiz system with 8+ security knowledge questions

## Data Flow

### Transaction Processing Flow
1. **Input Phase**: Player receives simulated banking transaction data
2. **Encryption Phase**: Apply AES-256 encryption to sensitive financial data
3. **Authentication Phase**: Generate and verify RSA digital signatures
4. **Integrity Check**: Create SHA-256 hash for tamper detection
5. **Validation Phase**: System verifies all security steps completed correctly
6. **Scoring Phase**: Award points based on accuracy and completion time

### Game Progression Flow
1. **Level System**: 10+ progressive difficulty levels
2. **Challenge Escalation**: Increasing transaction volume and complexity
3. **Upgrade Mechanics**: Purchase security tools using earned points
4. **Knowledge Validation**: Mini-quiz system for concept reinforcement

## External Dependencies

### Desktop Version Dependencies
- **PySide6**: Qt framework for Python GUI development
- **pycryptodome**: Production-grade cryptographic library
- **rsa**: RSA encryption implementation
- **Standard Library**: hashlib, base64, random, os modules

### Web Version Dependencies
- **None**: Self-contained HTML file with no external dependencies
- **Browser APIs**: Crypto.subtle for educational encryption demonstrations
- **Web Standards**: HTML5, CSS3, ES6 JavaScript features

## Deployment Strategy

### Development Environment
- **VS Code Integration**: Live Server extension for web development
- **Python Environment**: Virtual environment with pip requirements
- **Cross-Platform**: Supports Windows, macOS, and Linux

### Distribution Options
1. **Web Deployment**: Simple HTTP server or static hosting
2. **Desktop Distribution**: Executable packaging with PyInstaller
3. **Educational Deployment**: Classroom-ready with minimal setup requirements

### Hosting Considerations
- Web version requires no server-side processing
- Desktop version runs entirely offline
- No external API dependencies or database requirements

## Recent Updates (July 02, 2025)

### Major Improvements Completed:
✅ **Debug và Fix lỗi thuật toán**:
- Fixed AES encryption/decryption UTF-8 handling in crypto_utils.py
- Enhanced error handling và input validation
- Optimized crypto algorithm performance
- Improved UI/UX animation và styling

✅ **6 Mini Games mới được thêm**:
1. **Password Strength Game**: Tạo và kiểm tra mật khẩu mạnh
2. **Crypto Puzzle Game**: Giải mã Caesar, Vigenere, Reverse, Base64
3. **Phishing Detection Game**: Nhận diện email/URL lừa đảo
4. **Network Security Game**: Mô phỏng tấn công mạng và phòng thủ
5. **Hash Race Game**: Tìm hash collision với prefix cụ thể
6. **Social Engineering Defense**: Đối phó với kỹ thuật xã hội học

### Technical Architecture Updates:
- **Enhanced crypto_utils.py**: Improved AES encryption with proper padding and error handling
- **Responsive web interface**: securebank_pro.html với navigation tabs cho 6 mini games
- **Modern Python desktop app**: main.py với PySide6 GUI framework
- **Comprehensive styling**: modern_bank_style.qss cho desktop app
- **Educational focus**: Mỗi mini game dạy một khía cạnh khác nhau của cybersecurity

### Files Created/Updated:
- securebank_pro.html: Main web game với 6 mini games tích hợp
- main.py: Desktop application với PySide6
- crypto_utils.py: Enhanced crypto library với fixes
- modern_bank_style.qss: Professional banking theme
- README.md: Comprehensive documentation
- VSCODE_SETUP.md: VS Code setup instructions
- python_requirements.txt: Python dependencies

## Changelog

- July 02, 2025: Major update - Added 6 mini games, fixed crypto algorithms, enhanced UI/UX
- July 02, 2025: Initial setup

## User Preferences

Preferred communication style: Simple, everyday language (Vietnamese).
Request: Fix crypto algorithm bugs and add 6 interactive mini games to SecureBank Pro.
Project focus: Educational cybersecurity game for topic #23 - Banking Security System.