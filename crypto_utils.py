from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import base64
import hashlib
import hmac
import re

# --- Hàm mã hóa AES cải tiến ---
def encrypt_aes(data, key):
    """Mã hóa dữ liệu bằng AES ở chế độ CBC, trả về chuỗi base64 an toàn cho URL."""
    try:
        # Đảm bảo key có độ dài phù hợp (16, 24, hoặc 32 bytes)
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        # Chuẩn hóa key length
        if len(key) < 16:
            key = key.ljust(16, b'\0')
        elif len(key) < 24:
            key = key[:16]
        elif len(key) < 32:
            key = key[:24]
        else:
            key = key[:32]
            
        # Tạo IV ngẫu nhiên an toàn
        iv = get_random_bytes(16)
        
        # Mã hóa dữ liệu
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if isinstance(data, str):
            data = data.encode('utf-8')
        encrypted = cipher.encrypt(pad(data, 16))
        
        # Kết hợp IV và dữ liệu đã mã hóa
        result = base64.urlsafe_b64encode(iv + encrypted).decode('utf-8')
        return result
        
    except Exception as e:
        raise ValueError(f"Lỗi mã hóa AES: {str(e)}")

def decrypt_aes(ciphertext_b64, key):
    """Giải mã dữ liệu AES từ chuỗi base64, tự động sửa lỗi đệm."""
    try:
        # Chuẩn hóa key
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        if len(key) < 16:
            key = key.ljust(16, b'\0')
        elif len(key) < 24:
            key = key[:16]
        elif len(key) < 32:
            key = key[:24]
        else:
            key = key[:32]
        
        # Thêm đệm base64 nếu cần
        missing_padding = len(ciphertext_b64) % 4
        if missing_padding:
            ciphertext_b64 += '=' * (4 - missing_padding)
        
        # Giải mã base64
        try:
            ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Dữ liệu đầu vào không phải là base64 hợp lệ: {str(e)}")

        if len(ciphertext) < 32:  # IV (16) + ít nhất 1 block mã hóa (16)
            raise ValueError("Dữ liệu đầu vào quá ngắn để chứa IV và dữ liệu mã hóa.")

        # Tách IV và dữ liệu mã hóa
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        # Giải mã
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), 16)
        
        return decrypted.decode('utf-8')
        
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Lỗi giải mã. Khóa hoặc dữ liệu không chính xác: {str(e)}")

# --- Hàm tạo hash SHA-256 cải tiến ---
def create_hash(data):
    """Tạo hash SHA-256 cho dữ liệu"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def verify_hash(data, expected_hash):
    """Xác minh hash của dữ liệu"""
    actual_hash = create_hash(data)
    return hmac.compare_digest(actual_hash, expected_hash)

# --- Hàm mã hóa Vigenere cải tiến ---
def _vigenere_process(text, key, mode='encrypt'):
    """Hàm lõi xử lý mã hóa/giải mã Vigenere với hỗ trợ Unicode."""
    if not text or not key:
        return text
        
    result = []
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            # Xử lý ký tự alphabet
            is_upper = char.isupper()
            char = char.upper()
            
            key_char_shift = ord(key[key_index % len(key)]) - ord('A')
            char_offset = ord(char) - ord('A')
            
            if mode == 'encrypt':
                new_offset = (char_offset + key_char_shift) % 26
            else:
                new_offset = (char_offset - key_char_shift + 26) % 26
                
            new_char = chr(ord('A') + new_offset)
            if not is_upper:
                new_char = new_char.lower()
                
            result.append(new_char)
            key_index += 1
        else:
            result.append(char)
            
    return "".join(result)

def encrypt_vigenere(text, key):
    """Mã hóa văn bản bằng thuật toán Vigenere."""
    return _vigenere_process(text, key, mode='encrypt')

def decrypt_vigenere(text, key):
    """Giải mã văn bản bằng thuật toán Vigenere."""
    return _vigenere_process(text, key, mode='decrypt')

# --- Hàm mã hóa Caesar cải tiến ---
def encrypt_caesar(text, shift):
    """Mã hóa văn bản bằng thuật toán Caesar với hỗ trợ shift âm."""
    return _caesar_process(text, shift % 26)

def decrypt_caesar(text, shift):
    """Giải mã văn bản bằng thuật toán Caesar."""
    return _caesar_process(text, (-shift) % 26)

def _caesar_process(text, shift):
    """Xử lý mã hóa/giải mã Caesar"""
    result = []
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - ascii_offset + shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
    return ''.join(result)

# --- Hàm tạo mật khẩu mạnh ---
def generate_strong_password(length=12, include_symbols=True, include_numbers=True, include_uppercase=True, include_lowercase=True):
    """Tạo mật khẩu mạnh theo tiêu chí"""
    import random
    import string
    
    if length < 4:
        length = 4
        
    chars = ""
    password = []
    
    # Đảm bảo có ít nhất 1 ký tự từ mỗi loại được yêu cầu
    if include_lowercase:
        chars += string.ascii_lowercase
        password.append(random.choice(string.ascii_lowercase))
    
    if include_uppercase:
        chars += string.ascii_uppercase
        password.append(random.choice(string.ascii_uppercase))
    
    if include_numbers:
        chars += string.digits
        password.append(random.choice(string.digits))
    
    if include_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += symbols
        password.append(random.choice(symbols))
    
    # Thêm các ký tự ngẫu nhiên để đạt độ dài mong muốn
    for _ in range(length - len(password)):
        password.append(random.choice(chars))
    
    # Xáo trộn mật khẩu
    random.shuffle(password)
    return ''.join(password)

def check_password_strength(password):
    """Kiểm tra độ mạnh của mật khẩu"""
    score = 0
    feedback = []
    
    # Kiểm tra độ dài
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
        feedback.append("Nên dùng ít nhất 12 ký tự")
    else:
        feedback.append("Mật khẩu quá ngắn (cần ít nhất 8 ký tự)")
    
    # Kiểm tra chữ hoa
    if re.search(r'[A-Z]', password):
        score += 20
    else:
        feedback.append("Cần có chữ hoa")
    
    # Kiểm tra chữ thường
    if re.search(r'[a-z]', password):
        score += 20
    else:
        feedback.append("Cần có chữ thường")
    
    # Kiểm tra số
    if re.search(r'\d', password):
        score += 20
    else:
        feedback.append("Cần có số")
    
    # Kiểm tra ký tự đặc biệt
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        score += 15
    else:
        feedback.append("Nên có ký tự đặc biệt")
    
    # Đánh giá mức độ
    if score >= 90:
        strength = "Rất mạnh"
    elif score >= 70:
        strength = "Mạnh"
    elif score >= 50:
        strength = "Trung bình"
    elif score >= 30:
        strength = "Yếu"
    else:
        strength = "Rất yếu"
    
    return {
        'score': score,
        'strength': strength,
        'feedback': feedback
    }

# --- Hàm phát hiện phishing ---
def detect_phishing_url(url):
    """Phát hiện URL phishing đơn giản"""
    suspicious_patterns = [
        r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL rút gọn
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP address
        r'[a-z0-9-]+\.(tk|ml|ga|cf)',  # TLD miễn phí đáng nghi
        r'(paypal|amazon|google|facebook|microsoft)\w*\.(tk|ml|ga|cf|info|biz)',  # Giả mạo thương hiệu
        r'secure.*update|verify.*account|suspend.*account',  # Từ khóa phishing
        r'[a-z0-9]{20,}',  # Domain name quá dài và lạ
    ]
    
    risk_score = 0
    warnings = []
    
    url_lower = url.lower()
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url_lower):
            risk_score += 20
            if 'bit.ly' in pattern:
                warnings.append("URL rút gọn có thể ẩn địa chỉ thật")
            elif 'ip' in pattern:
                warnings.append("Sử dụng địa chỉ IP thay vì tên miền")
            elif 'tk|ml' in pattern:
                warnings.append("Sử dụng tên miền miễn phí đáng nghi")
            elif 'paypal' in pattern:
                warnings.append("Có thể giả mạo thương hiệu nổi tiếng")
            elif 'secure' in pattern:
                warnings.append("Chứa từ khóa phishing phổ biến")
            elif '{20,}' in pattern:
                warnings.append("Tên miền có độ dài bất thường")
    
    # Đánh giá mức độ nguy hiểm
    if risk_score >= 60:
        risk_level = "Cao"
    elif risk_score >= 40:
        risk_level = "Trung bình"
    elif risk_score >= 20:
        risk_level = "Thấp"
    else:
        risk_level = "An toàn"
    
    return {
        'risk_score': min(risk_score, 100),
        'risk_level': risk_level,
        'warnings': warnings,
        'is_suspicious': risk_score >= 40
    }

def detect_phishing_email(email_content):
    """Phát hiện email phishing"""
    suspicious_patterns = [
        r'urgent.*action.*required',
        r'verify.*account.*immediately',
        r'click.*here.*now',
        r'congratulations.*winner',
        r'limited.*time.*offer',
        r'suspended.*account',
        r'confirm.*identity',
        r'act.*now.*expire',
    ]
    
    risk_score = 0
    warnings = []
    
    content_lower = email_content.lower()
    
    for pattern in suspicious_patterns:
        if re.search(pattern, content_lower):
            risk_score += 15
            warnings.append(f"Chứa cụm từ đáng nghi: {pattern.replace('.*', ' ')}")
    
    # Kiểm tra links đáng nghi
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, email_content)
    
    for url in urls:
        url_result = detect_phishing_url(url)
        if url_result['is_suspicious']:
            risk_score += 25
            warnings.append(f"Chứa URL đáng nghi: {url}")
    
    if risk_score >= 60:
        risk_level = "Cao"
    elif risk_score >= 40:
        risk_level = "Trung bình"
    elif risk_score >= 20:
        risk_level = "Thấp"
    else:
        risk_level = "An toàn"
    
    return {
        'risk_score': min(risk_score, 100),
        'risk_level': risk_level,
        'warnings': warnings,
        'is_phishing': risk_score >= 40
    }

# --- Hash collision detection ---
def find_hash_prefix_collision(target_prefix, max_attempts=1000000):
    """Tìm hash collision với prefix cụ thể"""
    import random
    import time
    
    attempts = 0
    start_time = time.time()
    
    while attempts < max_attempts:
        # Tạo string ngẫu nhiên
        random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
        hash_result = create_hash(random_str)
        
        if hash_result.startswith(target_prefix):
            end_time = time.time()
            return {
                'success': True,
                'input': random_str,
                'hash': hash_result,
                'attempts': attempts + 1,
                'time_taken': end_time - start_time
            }
        
        attempts += 1
    
    end_time = time.time()
    return {
        'success': False,
        'attempts': attempts,
        'time_taken': end_time - start_time
    }