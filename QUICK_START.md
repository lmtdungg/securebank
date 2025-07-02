# 🚀 Hướng dẫn Khởi động Nhanh - SecureBank Pro

## 📁 Giải nén và Mở Project

```bash
# Giải nén file
tar -xzf SecureBank-Pro-Enhanced.tar.gz
cd SecureBank-Pro-Enhanced

# Mở trong VS Code
code .
```

## 🌐 Chạy Game Web (3 giây)

1. **Cách nhanh nhất**: Double-click `securebank_pro.html`
2. **Hoặc**: Click chuột phải → "Open with Live Server" (nếu có extension)
3. **Hoặc**: Chạy `python -m http.server 8000` → mở `localhost:8000/securebank_pro.html`

## 🐍 Chạy Game Desktop Python

```bash
# Cài dependencies
pip install PySide6 pycryptodome rsa

# Chạy game
python main.py
```

## 🎮 Cách Chơi

### Game Chính:
1. Bấm "🔑 Tạo khóa AES"
2. Nhập thông tin giao dịch
3. Bấm "🔒 Mã hóa" → "📨 Gửi"
4. Nhập khóa → "🔓 Giải mã"
5. Tạo OTP → "✅ Xác thực"

### 6 Mini Games:
- **🔐 Mật Khẩu**: Tạo password mạnh
- **🧩 Crypto**: Giải mã Caesar/Vigenere
- **🎣 Phishing**: Phát hiện email lừa đảo
- **🌐 Mạng**: Bảo vệ network
- **⚡ Hash**: Tìm hash collision
- **👥 Xã Hội**: Đối phó social engineering

## ✅ Tính năng Đã Fix

- ✅ AES encryption UTF-8 handling
- ✅ Enhanced error handling
- ✅ Input validation improvements
- ✅ 6 mini games hoàn chỉnh
- ✅ Modern UI với animations
- ✅ Cross-platform compatibility

## 📞 Hỗ trợ

- 📖 README.md: Hướng dẫn chi tiết
- 🔧 VSCODE_SETUP.md: Setup VS Code
- 📋 replit.md: Technical documentation

**Chúc bạn chơi game vui vẻ! 🎉**