# 🔧 Hướng dẫn Chạy SecureBank Pro trong VS Code

## 📋 Yêu cầu

- Visual Studio Code
- Extension Live Server (cho phiên bản web)
- Python 3.8+ (cho phiên bản desktop)

## 🚀 Cách 1: Chạy phiên bản Web (Khuyến nghị)

### Bước 1: Mở Project trong VS Code
```bash
# Giải nén file zip đã tải
unzip SecureBank-Pro.zip
cd SecureBank-Pro

# Mở trong VS Code
code .
```

### Bước 2: Cài đặt Live Server Extension
1. Mở VS Code
2. Bấm `Ctrl+Shift+X` (Windows/Linux) hoặc `Cmd+Shift+X` (Mac)
3. Search "Live Server" 
4. Cài extension của Ritwick Dey

### Bước 3: Chạy Game
1. **Cách 1 - Live Server:**
   - Click chuột phải vào file `securebank_pro.html`
   - Chọn "Open with Live Server"
   - Game sẽ mở tự động trong browser

2. **Cách 2 - Python Server:**
   ```bash
   # Mở terminal trong VS Code (Ctrl+`)
   python -m http.server 8000
   
   # Truy cập: http://localhost:8000/securebank_pro.html
   ```

3. **Cách 3 - Trực tiếp:**
   - Double-click file `securebank_pro.html`
   - Hoặc kéo thả vào browser

## 🐍 Cách 2: Chạy phiên bản Python Desktop

### Bước 1: Cài đặt Python Extension
1. Mở VS Code
2. Cài extension "Python" của Microsoft
3. Cài extension "Python Debugger"

### Bước 2: Tạo Virtual Environment
```bash
# Mở terminal trong VS Code
python -m venv venv

# Kích hoạt virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### Bước 3: Cài đặt Dependencies
```bash
pip install -r python_requirements.txt
```

### Bước 4: Chạy Game
```bash
python main.py
```

Hoặc:
1. Mở file `main.py` trong VS Code
2. Bấm `F5` để debug
3. Hoặc bấm `Ctrl+F5` để chạy không debug

## ⚙️ Cấu hình VS Code

### 1. Tạo file `.vscode/launch.json` (Cho Python)
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "SecureBank Pro",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

### 2. Tạo file `.vscode/settings.json`
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.terminal.activateEnvironment": true,
    "liveServer.settings.port": 8000,
    "liveServer.settings.root": "/",
    "files.associations": {
        "*.html": "html"
    }
}
```

### 3. Tạo file `.vscode/tasks.json`
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Run SecureBank Web",
            "type": "shell",
            "command": "python",
            "args": ["-m", "http.server", "8000"],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "new"
            },
            "problemMatcher": []
        },
        {
            "label": "Run SecureBank Desktop",
            "type": "shell",
            "command": "python",
            "args": ["main.py"],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "new"
            },
            "problemMatcher": []
        }
    ]
}
```

## 🔧 Debug và Development

### Debug Web Version:
1. Mở Developer Tools (`F12`)
2. Console tab để xem logs
3. Sources tab để debug JavaScript
4. Network tab để kiểm tra requests

### Debug Python Version:
1. Đặt breakpoints bằng cách click vào số dòng
2. Bấm `F5` để start debug
3. Sử dụng Debug Console để test code
4. Watch variables trong Debug panel

### Hot Reload:
- **Web**: Live Server tự động reload khi save file
- **Python**: Cần restart manually sau khi sửa code

## 📁 Cấu trúc Project

```
SecureBank-Pro/
├── .vscode/                    # VS Code configuration
│   ├── launch.json            # Debug configuration
│   ├── settings.json          # Workspace settings
│   └── tasks.json            # Build tasks
├── venv/                      # Python virtual environment
├── securebank_pro.html        # ⭐ GAME CHÍNH (Web version)
├── main.py                    # Python desktop version
├── crypto_utils.py           # Crypto functions
├── modern_bank_style.qss     # Qt stylesheet
├── python_requirements.txt   # Python dependencies
├── README.md                 # Hướng dẫn chính
├── VSCODE_SETUP.md          # File này
└── replit.md                # Technical docs
```

## 🚨 Xử lý Lỗi

### Lỗi phổ biến:

1. **"Live Server not found"**
   ```
   Giải pháp: Cài extension Live Server từ VS Code Marketplace
   ```

2. **"Python not found"**
   ```
   Giải pháp: 
   - Cài Python từ python.org
   - Hoặc sử dụng phiên bản web (không cần Python)
   ```

3. **"Module not found"**
   ```bash
   pip install -r python_requirements.txt
   ```

4. **Port 8000 đã được sử dụng**
   ```bash
   # Sử dụng port khác
   python -m http.server 8080
   ```

5. **PySide6 install failed**
   ```bash
   # Thử cách khác
   pip install --upgrade pip
   pip install PySide6 --force-reinstall
   ```

## 💡 Tips cho VS Code

### Shortcuts hữu ích:
- `Ctrl+Shift+P`: Command Palette
- `Ctrl+`` `: Toggle Terminal
- `F12`: Go to Definition
- `Ctrl+Space`: IntelliSense
- `Alt+Shift+F`: Format Document
- `Ctrl+/`: Toggle Comment

### Extensions khuyến nghị:
- **Live Server**: Cho web development
- **Python**: Python support
- **HTML CSS Support**: HTML/CSS IntelliSense
- **JavaScript (ES6) code snippets**: JS snippets
- **Prettier**: Code formatter
- **GitLens**: Git integration

### Theme khuyến nghị:
- **Dark+ (default dark)**: VS Code default
- **Monokai**: Classic dark theme
- **One Dark Pro**: Atom-inspired theme

## 🎮 Bắt đầu chơi

1. **Khuyến nghị**: Sử dụng phiên bản web (`securebank_pro.html`)
   - Dễ setup nhất
   - Không cần cài Python
   - Giao diện đẹp và mượt mà
   - Có đầy đủ 6 mini games

2. **Advanced**: Phiên bản Python desktop (`main.py`)
   - Có thêm tính năng desktop
   - Hiệu năng tốt hơn
   - Cần setup Python environment

## 🆕 Tính năng mới trong phiên bản này

### ✅ Fixes và Improvements:
- **Fixed AES encryption**: Cải thiện xử lý UTF-8 và padding
- **Enhanced error handling**: Xử lý lỗi toàn diện
- **Better input validation**: Kiểm tra dữ liệu chặt chẽ hơn
- **Optimized crypto algorithms**: Tối ưu hóa performance

### 🎮 6 Mini Games mới:
1. **🔐 Password Strength Game**: Tạo mật khẩu mạnh
2. **🧩 Crypto Puzzle**: Giải mã Caesar, Vigenere, Base64
3. **🎣 Phishing Detection**: Nhận diện email/URL giả mạo
4. **🌐 Network Security**: Mô phỏng tấn công và phòng thủ mạng
5. **⚡ Hash Race**: Tìm hash collision nhanh nhất
6. **👥 Social Engineering Defense**: Đối phó kỹ thuật xã hội

### 🎨 UI/UX Improvements:
- **Modern Banking Theme**: Màu sắc chuyên nghiệp
- **Particle Animations**: Hiệu ứng particles vàng
- **Smooth Transitions**: Chuyển đổi mượt mà
- **Responsive Design**: Tương thích mobile

**🚀 Chúc bạn code vui vẻ và chơi game thành công!**