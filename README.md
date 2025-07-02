# 🏦 SecureBank Pro - Game Bảo mật Ngân hàng Chuyên nghiệp

## 📋 Giới thiệu

SecureBank Pro là một trò chơi giáo dục mô phỏng hệ thống bảo mật ngân hàng hiện đại. Người chơi sẽ đóng vai một chuyên viên bảo mật, thực hiện các giao dịch an toàn và trải nghiệm 6 mini games tương tác về bảo mật thông tin.

## ✨ Tính năng chính

### 🔐 Hệ thống Mã hóa
- **AES-256 Encryption**: Mã hóa dữ liệu giao dịch với thuật toán AES-256
- **SHA-256 Hashing**: Tạo fingerprint cho dữ liệu
- **OTP Authentication**: Xác thực 2 lớp với mã OTP 6 chữ số
- **RSA Support**: Hỗ trợ mã hóa bất đối xứng (trong phiên bản Python)

### 🎮 6 Mini Games Tương Tác
1. **🔐 Password Strength Game**: Tạo mật khẩu mạnh theo tiêu chí an toàn
2. **🧩 Crypto Puzzle**: Giải mã các cipher đơn giản (Caesar, Vigenere, Base64)
3. **🎣 Phishing Detection**: Nhận diện email/website giả mạo
4. **🌐 Network Security**: Mô phỏng tấn công mạng và phòng thủ
5. **⚡ Hash Race**: Tìm hash collision nhanh nhất
6. **👥 Social Engineering Defense**: Đối phó với kỹ thuật xã hội học

### 🛡️ Công cụ Bảo mật
- **Phát hiện Phishing**: Kiểm tra URL và email đáng nghi
- **Hash Generator**: Tạo hash SHA-256 cho dữ liệu
- **Transaction Monitor**: Theo dõi lịch sử giao dịch
- **Data Export/Import**: Sao lưu và khôi phục tiến trình

### 🎨 Giao diện Hiện đại
- **Banking Theme**: Màu sắc chuyên nghiệp ngân hàng
- **Particles Animation**: Hiệu ứng particles vàng động
- **Gradient Background**: Nền gradient chuyển động
- **Responsive Design**: Tương thích mobile và desktop
- **Smooth Animations**: Các hiệu ứng mượt mà

## 🚀 Cách chạy

### Phiên bản Web (Khuyến nghị)
1. Mở file `securebank_pro.html` trong trình duyệt web
2. Hoặc chạy server local:
   ```bash
   python -m http.server 8000
   ```
3. Truy cập `http://localhost:8000/securebank_pro.html`

### Phiên bản Python (Desktop)
1. Cài đặt dependencies:
   ```bash
   pip install -r python_requirements.txt
   ```
2. Chạy game:
   ```bash
   python main.py
   ```

## 📁 Cấu trúc Project

```
SecureBank-Pro/
├── securebank_pro.html      # Phiên bản web chính (KHUYẾN NGHỊ)
├── main.py                  # Phiên bản Python desktop
├── crypto_utils.py          # Thư viện mã hóa cải tiến
├── modern_bank_style.qss    # Stylesheet cho Python
├── python_requirements.txt  # Python dependencies
├── README.md                # Hướng dẫn này
├── VSCODE_SETUP.md         # Hướng dẫn VS Code
└── replit.md               # Tài liệu kỹ thuật
```

## 🎯 Hướng dẫn chơi

### 1. Quy trình Giao dịch Cơ bản
1. **Tạo khóa AES**: Bấm "🔑 Tạo khóa AES" để tạo khóa mã hóa 256-bit
2. **Nhập thông tin**: 
   - Số tài khoản (9-12 chữ số)
   - Số tiền (VND)
   - Nội dung chuyển khoản
3. **Mã hóa**: Bấm "🔒 Mã hóa dữ liệu" để bảo mật thông tin
4. **Gửi**: Bấm "📨 Gửi giao dịch" để truyền dữ liệu
5. **Giải mã**: Nhập khóa AES và bấm "🔓 Giải mã dữ liệu"
6. **OTP**: Bấm "📱 Tạo mã OTP" và nhập mã 6 chữ số
7. **Xác thực**: Bấm "✅ Xác thực giao dịch" để hoàn tất

### 2. Mini Games
- **Password Game**: Tạo mật khẩu mạnh với các tiêu chí khác nhau
- **Crypto Puzzle**: Giải mã các thuật toán mã hóa cổ điển
- **Phishing Detection**: Phân biệt email thật và giả
- **Network Security**: Bảo vệ mạng khỏi tấn công
- **Hash Race**: Tìm hash có prefix cụ thể
- **Social Defense**: Đối phó với lừa đảo xã hội

## 🏆 Hệ thống Điểm

| Hoạt động | Điểm thưởng |
|-----------|-------------|
| Tạo khóa AES | +10 điểm |
| Mã hóa thành công | +20 điểm |
| Giải mã thành công | +30 điểm |
| Hoàn thành giao dịch | +100-300 điểm |
| Mini games | +15-50 điểm |
| Bonus level | +50-500 điểm |

## 🔒 Cải tiến Bảo mật

### Fixes và Improvements:
- ✅ **Fixed AES encryption**: Cải thiện xử lý UTF-8 và padding
- ✅ **Enhanced error handling**: Xử lý lỗi toàn diện
- ✅ **Improved input validation**: Kiểm tra dữ liệu đầu vào chặt chẽ
- ✅ **Optimized performance**: Tối ưu hóa thuật toán crypto
- ✅ **Better UI/UX**: Giao diện người dùng cải tiến
- ✅ **6 new mini games**: Thêm 6 trò chơi tương tác mới

### Security Features:
- 🔐 **AES-256 CBC**: Mã hóa đối xứng an toàn
- 🔑 **RSA-2048**: Mã hóa bất đối xứng (Python version)
- 🔨 **SHA-256**: Hash function cho integrity check
- 📱 **OTP System**: Xác thực 2 lớp
- 🛡️ **Phishing Detection**: Phát hiện lừa đảo
- 🌐 **Network Security**: Mô phỏng bảo mật mạng

## ⚙️ Yêu cầu Hệ thống

### Phiên bản Web
- Trình duyệt hiện đại (Chrome, Firefox, Safari, Edge)
- JavaScript enabled
- Không cần cài đặt thêm

### Phiên bản Python
- Python 3.8+ 
- PySide6 (GUI framework)
- pycryptodome (mã hóa)
- rsa (RSA encryption)
- RAM: 4GB+
- Ổ cứng: 100MB

## 🐛 Troubleshooting

### Lỗi thường gặp:
1. **Import Error**: Cài đặt dependencies đúng cách
2. **Encoding Error**: Đã fix trong phiên bản mới
3. **UI không hiển thị**: Kiểm tra file .qss stylesheet

### Debug:
- Mở Developer Tools (F12) để xem console logs
- Kiểm tra file README cho troubleshooting

## 🎓 Mục tiêu Giáo dục

Game giúp người chơi hiểu về:
- Thuật toán mã hóa cơ bản (AES, RSA, SHA)
- Quy trình bảo mật giao dịch ngân hàng
- Phát hiện và phòng chống phishing
- Tạo mật khẩu mạnh
- Bảo mật mạng máy tính
- Kỹ thuật xã hội và cách phòng thủ

## 📜 License

MIT License - Sử dụng tự do cho mục đích giáo dục và thương mại.

## 👨‍💻 Tác giả

Phát triển bởi SecureBank Team với mục tiêu giáo dục về bảo mật thông tin.

## 🚀 Phiên bản tiếp theo

- [ ] Multiplayer mode
- [ ] Blockchain integration  
- [ ] AI opponent
- [ ] Mobile app
- [ ] Advanced cryptography algorithms
- [ ] Real-time collaborative security challenges

---

**🎮 Chúc bạn chơi game vui vẻ và học được nhiều kiến thức bảo mật!**