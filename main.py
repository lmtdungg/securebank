import sys
import random
import string
import hashlib
import base64
import json
import os
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QLabel, QLineEdit, QPushButton, QFrame, QGridLayout, 
                               QStackedWidget, QMessageBox, QProgressBar, QListWidget,
                               QSizePolicy, QListWidgetItem, QGraphicsOpacityEffect, 
                               QGraphicsDropShadowEffect, QTextEdit, QCheckBox, QSlider,
                               QComboBox, QTabWidget, QSplitter, QGroupBox, QScrollArea)
from PySide6.QtGui import (QColor, QPainter, QPen, QBrush, QLinearGradient, QFont, 
                           QPalette, QPixmap, QIcon)
from PySide6.QtCore import (Qt, Slot, QTimer, QTime, QPropertyAnimation, QEasingCurve, 
                            QRect, QParallelAnimationGroup, QSequentialAnimationGroup,
                            QThread, Signal)
from crypto_utils import (encrypt_aes, decrypt_aes, create_hash, verify_hash,
                          encrypt_vigenere, decrypt_vigenere, encrypt_caesar, decrypt_caesar,
                          generate_strong_password, check_password_strength,
                          detect_phishing_url, detect_phishing_email,
                          find_hash_prefix_collision)

class AnimatedBackground(QWidget):
    """Widget nền với hiệu ứng động gradient và particles"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = []
        self.init_particles()
        self.gradient_offset = 0
        
        # Timer cho animation
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self.update_animation)
        self.animation_timer.start(50)  # 50ms refresh rate
        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def init_particles(self):
        """Khởi tạo các particles cho hiệu ứng nền"""
        for _ in range(50):
            particle = {
                'x': random.randint(0, 1920),
                'y': random.randint(0, 1080),
                'size': random.randint(1, 3),
                'speed_x': random.uniform(-0.5, 0.5),
                'speed_y': random.uniform(-0.5, 0.5),
                'opacity': random.randint(30, 100)
            }
            self.particles.append(particle)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Gradient nền động
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor(15, 32, 62))  # Xanh đậm
        gradient.setColorAt(0.5, QColor(25, 55, 109))  # Xanh ngân hàng
        gradient.setColorAt(1, QColor(35, 47, 68))  # Xám xanh
        
        painter.fillRect(self.rect(), gradient)
        
        # Vẽ particles
        for particle in self.particles:
            painter.setBrush(QBrush(QColor(255, 215, 0, particle['opacity'])))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(int(particle['x']), int(particle['y']), 
                              particle['size'], particle['size'])

    def update_animation(self):
        """Cập nhật vị trí particles"""
        for particle in self.particles:
            particle['x'] += particle['speed_x']
            particle['y'] += particle['speed_y']
            
            # Reset particle khi ra khỏi màn hình
            if particle['x'] < 0 or particle['x'] > self.width():
                particle['x'] = random.randint(0, self.width())
            if particle['y'] < 0 or particle['y'] > self.height():
                particle['y'] = random.randint(0, self.height())
        
        self.update()

class GameStatsWidget(QWidget):
    """Widget hiển thị thống kê game"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QGridLayout(self)
        
        # Tạo các stat cards
        stats = [
            ("📊", "Tổng Điểm", "totalScore", 0),
            ("🎯", "Level", "currentLevel", 1),
            ("🔒", "Giao Dịch", "completedTransactions", 0),
            ("🏆", "Thành Tích", "achievements", 0),
            ("⭐", "Chuỗi Thắng", "streak", 0)
        ]
        
        self.stat_labels = {}
        
        for i, (icon, label, key, default_value) in enumerate(stats):
            frame = self.create_stat_card(icon, label, default_value)
            self.stat_labels[key] = frame.findChild(QLabel, "value")
            layout.addWidget(frame, 0, i)
            
    def create_stat_card(self, icon, label, value):
        frame = QFrame()
        frame.setObjectName("StatCard")
        frame.setFixedSize(150, 120)
        
        layout = QVBoxLayout(frame)
        
        icon_label = QLabel(icon)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 32px; margin-bottom: 10px;")
        
        value_label = QLabel(str(value))
        value_label.setObjectName("value")
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #FFD700; margin-bottom: 5px;")
        
        label_label = QLabel(label)
        label_label.setAlignment(Qt.AlignCenter)
        label_label.setStyleSheet("font-size: 12px; color: #b0bec5;")
        
        layout.addWidget(icon_label)
        layout.addWidget(value_label)
        layout.addWidget(label_label)
        
        return frame
        
    def update_stats(self, stats):
        """Cập nhật hiển thị thống kê"""
        for key, value in stats.items():
            if key in self.stat_labels:
                self.stat_labels[key].setText(str(value))

class PasswordGameWidget(QWidget):
    """Mini game tạo mật khẩu mạnh"""
    def __init__(self, game_manager):
        super().__init__()
        self.game_manager = game_manager
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔐 Game Tạo Mật Khẩu Mạnh")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)
        
        # Password input
        input_group = QGroupBox("Nhập mật khẩu của bạn:")
        input_layout = QVBoxLayout(input_group)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.check_password_strength)
        input_layout.addWidget(self.password_input)
        
        # Show/Hide button
        show_btn = QPushButton("👁️ Hiện/Ẩn")
        show_btn.clicked.connect(self.toggle_password_visibility)
        input_layout.addWidget(show_btn)
        
        layout.addWidget(input_group)
        
        # Strength meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        layout.addWidget(self.strength_bar)
        
        # Feedback
        self.feedback_label = QLabel()
        self.feedback_label.setWordWrap(True)
        layout.addWidget(self.feedback_label)
        
        # Password generator
        generator_group = QGroupBox("Tạo mật khẩu tự động:")
        generator_layout = QVBoxLayout(generator_group)
        
        # Options
        options_layout = QHBoxLayout()
        self.include_upper = QCheckBox("Chữ hoa")
        self.include_lower = QCheckBox("Chữ thường") 
        self.include_numbers = QCheckBox("Số")
        self.include_symbols = QCheckBox("Ký tự đặc biệt")
        
        for checkbox in [self.include_upper, self.include_lower, self.include_numbers, self.include_symbols]:
            checkbox.setChecked(True)
            options_layout.addWidget(checkbox)
            
        generator_layout.addLayout(options_layout)
        
        # Length slider
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Độ dài:"))
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(32)
        self.length_slider.setValue(12)
        self.length_slider.valueChanged.connect(self.update_length_display)
        length_layout.addWidget(self.length_slider)
        
        self.length_display = QLabel("12")
        length_layout.addWidget(self.length_display)
        
        generator_layout.addLayout(length_layout)
        
        # Generate button
        generate_btn = QPushButton("🎲 Tạo mật khẩu")
        generate_btn.clicked.connect(self.generate_password)
        generator_layout.addWidget(generate_btn)
        
        # Generated password
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        generator_layout.addWidget(self.generated_password)
        
        layout.addWidget(generator_group)
        
        # Challenge section
        challenge_group = QGroupBox("🏆 Thử thách mật khẩu:")
        challenge_layout = QVBoxLayout(challenge_group)
        
        self.challenge_label = QLabel()
        self.challenge_label.setWordWrap(True)
        challenge_layout.addWidget(self.challenge_label)
        
        challenge_btn = QPushButton("🎯 Bắt đầu thử thách")
        challenge_btn.clicked.connect(self.start_challenge)
        challenge_layout.addWidget(challenge_btn)
        
        layout.addWidget(challenge_group)
        
        # Start first challenge
        self.start_challenge()
        
    def toggle_password_visibility(self):
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            
    def check_password_strength(self):
        password = self.password_input.text()
        if not password:
            self.strength_bar.setValue(0)
            self.feedback_label.setText("")
            return
            
        result = check_password_strength(password)
        self.strength_bar.setValue(result['score'])
        
        # Update color based on strength
        if result['score'] >= 80:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #28a745; }")
        elif result['score'] >= 60:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }")
        elif result['score'] >= 40:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #fd7e14; }")
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #dc3545; }")
            
        feedback_text = f"Độ mạnh: {result['strength']} ({result['score']}/100)\n"
        if result['feedback']:
            feedback_text += "Cần cải thiện:\n" + "\n".join(f"• {fb}" for fb in result['feedback'])
        else:
            feedback_text += "✅ Mật khẩu rất tốt!"
            
        self.feedback_label.setText(feedback_text)
        
    def update_length_display(self):
        self.length_display.setText(str(self.length_slider.value()))
        
    def generate_password(self):
        length = self.length_slider.value()
        include_symbols = self.include_symbols.isChecked()
        include_numbers = self.include_numbers.isChecked()
        include_uppercase = self.include_upper.isChecked()
        include_lowercase = self.include_lower.isChecked()
        
        password = generate_strong_password(
            length, include_symbols, include_numbers, 
            include_uppercase, include_lowercase
        )
        
        self.generated_password.setText(password)
        self.game_manager.add_score(15, "Tạo mật khẩu mạnh")
        
    def start_challenge(self):
        challenges = [
            "Tạo mật khẩu có ít nhất 10 ký tự với chữ hoa, chữ thường và số",
            "Tạo mật khẩu mạnh không chứa từ trong từ điển", 
            "Tạo mật khẩu có ít nhất 12 ký tự với tất cả loại ký tự",
            "Tạo mật khẩu dễ nhớ nhưng khó đoán"
        ]
        
        challenge = random.choice(challenges)
        self.challenge_label.setText(f"Thử thách: {challenge}")

class CryptoPuzzleWidget(QWidget):
    """Mini game giải mã crypto"""
    def __init__(self, game_manager):
        super().__init__()
        self.game_manager = game_manager
        self.current_puzzle = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🧩 Game Giải Mã Crypto")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)
        
        # Cipher type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Chọn loại mã hóa:"))
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems(["Caesar Cipher", "Vigenere Cipher", "Reverse Text", "Base64"])
        self.cipher_combo.currentTextChanged.connect(self.generate_puzzle)
        type_layout.addWidget(self.cipher_combo)
        layout.addLayout(type_layout)
        
        # Encrypted text
        self.encrypted_text = QTextEdit()
        self.encrypted_text.setMaximumHeight(100)
        self.encrypted_text.setReadOnly(True)
        layout.addWidget(QLabel("Văn bản đã mã hóa:"))
        layout.addWidget(self.encrypted_text)
        
        # Hint
        self.hint_label = QLabel()
        self.hint_label.setStyleSheet("color: #FFD700; font-style: italic;")
        layout.addWidget(self.hint_label)
        
        # Solution input
        layout.addWidget(QLabel("Nhập kết quả giải mã:"))
        self.solution_input = QTextEdit()
        self.solution_input.setMaximumHeight(100)
        layout.addWidget(self.solution_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        new_puzzle_btn = QPushButton("🎲 Tạo câu đố mới")
        new_puzzle_btn.clicked.connect(self.generate_puzzle)
        button_layout.addWidget(new_puzzle_btn)
        
        check_btn = QPushButton("✅ Kiểm tra")
        check_btn.clicked.connect(self.check_solution)
        button_layout.addWidget(check_btn)
        
        hint_btn = QPushButton("💡 Gợi ý")
        hint_btn.clicked.connect(self.show_hint)
        button_layout.addWidget(hint_btn)
        
        layout.addLayout(button_layout)
        
        # Result
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)
        
        # Generate first puzzle
        self.generate_puzzle()
        
    def generate_puzzle(self):
        cipher_type = self.cipher_combo.currentText()
        
        texts = [
            "HELLO WORLD",
            "SECURITY FIRST", 
            "CRYPTOGRAPHY IS AMAZING",
            "PROTECT YOUR DATA",
            "BLOCKCHAIN TECHNOLOGY"
        ]
        
        original_text = random.choice(texts)
        
        if cipher_type == "Caesar Cipher":
            shift = random.randint(1, 25)
            encrypted = self.caesar_encrypt(original_text, shift)
            hint = f"Caesar cipher với shift = {shift}"
        elif cipher_type == "Vigenere Cipher":
            key = random.choice(["BANK", "SAFE", "GOLD", "LOCK"])
            encrypted = encrypt_vigenere(original_text, key)
            hint = f"Vigenere cipher với khóa = {key}"
        elif cipher_type == "Reverse Text":
            encrypted = original_text[::-1]
            hint = "Văn bản đã được đảo ngược"
        else:  # Base64
            encrypted = base64.b64encode(original_text.encode()).decode()
            hint = "Dữ liệu được mã hóa Base64"
            
        self.current_puzzle = {
            'original': original_text,
            'encrypted': encrypted,
            'hint': hint,
            'type': cipher_type
        }
        
        self.encrypted_text.setText(encrypted)
        self.hint_label.setText("")
        self.solution_input.setText("")
        self.result_label.setText("")
        
    def caesar_encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
        
    def check_solution(self):
        if not self.current_puzzle:
            return
            
        user_solution = self.solution_input.toPlainText().upper().strip()
        correct_solution = self.current_puzzle['original'].upper()
        
        if user_solution == correct_solution:
            self.result_label.setText(f"🎉 Chính xác! Bạn đã giải mã thành công: {correct_solution}")
            self.result_label.setStyleSheet("color: #28a745; font-weight: bold;")
            self.game_manager.add_score(30, "Giải mã thành công")
        else:
            self.result_label.setText(f"❌ Chưa đúng. Kết quả của bạn: {user_solution}\nHãy thử lại hoặc xem gợi ý!")
            self.result_label.setStyleSheet("color: #dc3545;")
            
    def show_hint(self):
        if self.current_puzzle:
            self.hint_label.setText(self.current_puzzle['hint'])
            self.game_manager.add_score(5, "Xem gợi ý")

class HashRaceWidget(QWidget):
    """Mini game Hash Race"""
    def __init__(self, game_manager):
        super().__init__()
        self.game_manager = game_manager
        self.race_active = False
        self.attempts = 0
        self.successes = 0
        self.start_time = None
        self.target_prefix = "00"
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("⚡ Game Hash Race")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)
        
        # Challenge display
        challenge_group = QGroupBox("🎯 Thử thách hiện tại:")
        challenge_layout = QVBoxLayout(challenge_group)
        
        self.challenge_label = QLabel(f"Tìm chuỗi có hash SHA-256 bắt đầu bằng: {self.target_prefix}")
        challenge_layout.addWidget(self.challenge_label)
        
        layout.addWidget(challenge_group)
        
        # Timer
        self.timer_label = QLabel("00:00")
        self.timer_label.setAlignment(Qt.AlignCenter)
        self.timer_label.setStyleSheet("font-size: 24px; color: #FFD700; font-weight: bold;")
        layout.addWidget(self.timer_label)
        
        # Input
        layout.addWidget(QLabel("Nhập chuỗi để thử:"))
        self.hash_input = QLineEdit()
        layout.addWidget(self.hash_input)
        
        # Hash result
        layout.addWidget(QLabel("Hash SHA-256:"))
        self.hash_result = QLineEdit()
        self.hash_result.setReadOnly(True)
        layout.addWidget(self.hash_result)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        calculate_btn = QPushButton("🔨 Tính Hash")
        calculate_btn.clicked.connect(self.calculate_hash)
        button_layout.addWidget(calculate_btn)
        
        start_btn = QPushButton("🏁 Bắt đầu cuộc đua")
        start_btn.clicked.connect(self.start_race)
        button_layout.addWidget(start_btn)
        
        auto_btn = QPushButton("🤖 Tìm kiếm tự động")
        auto_btn.clicked.connect(self.auto_search)
        button_layout.addWidget(auto_btn)
        
        stop_btn = QPushButton("⏹️ Dừng")
        stop_btn.clicked.connect(self.stop_race)
        button_layout.addWidget(stop_btn)
        
        layout.addLayout(button_layout)
        
        # Stats
        stats_group = QGroupBox("📊 Thống kê:")
        stats_layout = QGridLayout(stats_group)
        
        self.attempts_label = QLabel("0")
        self.successes_label = QLabel("0")
        self.best_time_label = QLabel("--")
        self.hash_rate_label = QLabel("0")
        
        stats_layout.addWidget(QLabel("Lần thử:"), 0, 0)
        stats_layout.addWidget(self.attempts_label, 0, 1)
        stats_layout.addWidget(QLabel("Thành công:"), 0, 2)
        stats_layout.addWidget(self.successes_label, 0, 3)
        stats_layout.addWidget(QLabel("Thời gian tốt nhất:"), 1, 0)
        stats_layout.addWidget(self.best_time_label, 1, 1)
        stats_layout.addWidget(QLabel("Hash/giây:"), 1, 2)
        stats_layout.addWidget(self.hash_rate_label, 1, 3)
        
        layout.addWidget(stats_group)
        
        # Success history
        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(150)
        layout.addWidget(QLabel("🏆 Lịch sử thành công:"))
        layout.addWidget(self.history_list)
        
        # Timer for updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        
    def start_race(self):
        self.race_active = True
        self.attempts = 0
        self.start_time = datetime.now()
        
        # Generate new target
        prefixes = ['0', '00', '000', '1', '11', 'a', 'ab', 'ff']
        self.target_prefix = random.choice(prefixes)
        self.challenge_label.setText(f"Tìm chuỗi có hash SHA-256 bắt đầu bằng: {self.target_prefix}")
        
        self.timer.start(1000)
        self.game_manager.show_notification(f"Hash Race bắt đầu! Tìm hash bắt đầu bằng '{self.target_prefix}'")
        
    def stop_race(self):
        self.race_active = False
        self.timer.stop()
        
    def calculate_hash(self):
        input_text = self.hash_input.text()
        if not input_text:
            return
            
        hash_result = create_hash(input_text)
        self.hash_result.setText(hash_result)
        
        if self.race_active:
            self.attempts += 1
            
            if hash_result.startswith(self.target_prefix):
                # Success!
                self.successes += 1
                elapsed = (datetime.now() - self.start_time).total_seconds()
                
                self.game_manager.add_score(50 + len(self.target_prefix) * 20, "Tìm thấy hash collision")
                self.game_manager.show_notification(f"🎉 Tìm thấy! Hash: {hash_result}")
                
                # Add to history
                item = QListWidgetItem(f"{input_text} → {hash_result[:16]}... (Thời gian: {elapsed:.2f}s)")
                self.history_list.addItem(item)
                
                # Start new challenge
                QTimer.singleShot(2000, self.start_race)
                
            self.update_stats()
            
    def auto_search(self):
        if self.race_active:
            random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            self.hash_input.setText(random_string)
            self.calculate_hash()
            QTimer.singleShot(100, self.auto_search)
            
    def update_timer(self):
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            self.timer_label.setText(f"{minutes:02d}:{seconds:02d}")
            
    def update_stats(self):
        self.attempts_label.setText(str(self.attempts))
        self.successes_label.setText(str(self.successes))
        
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > 0:
                rate = self.attempts / elapsed
                self.hash_rate_label.setText(f"{rate:.1f}")

class NetworkSecurityWidget(QWidget):
    """Mini game bảo mật mạng"""
    def __init__(self, game_manager):
        super().__init__()
        self.game_manager = game_manager
        self.network_nodes = []
        self.game_active = False
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🌐 Game Bảo Mật Mạng")
        title.setObjectName("PanelTitle")
        layout.addWidget(title)
        
        # Network grid
        grid_group = QGroupBox("🖥️ Mạng máy tính của bạn:")
        grid_layout = QVBoxLayout(grid_group)
        
        self.network_grid = QGridLayout()
        grid_widget = QWidget()
        grid_widget.setLayout(self.network_grid)
        grid_layout.addWidget(grid_widget)
        
        layout.addWidget(grid_group)
        
        # Status
        status_layout = QHBoxLayout()
        self.safe_label = QLabel("🟢 An toàn: 0")
        self.infected_label = QLabel("🔴 Bị nhiễm: 0")
        self.protected_label = QLabel("🛡️ Được bảo vệ: 0")
        
        status_layout.addWidget(self.safe_label)
        status_layout.addWidget(self.infected_label)
        status_layout.addWidget(self.protected_label)
        
        layout.addLayout(status_layout)
        
        # Tools
        tools_group = QGroupBox("Công cụ bảo mật:")
        tools_layout = QHBoxLayout(tools_group)
        
        firewall_btn = QPushButton("🔥 Triển khai Firewall")
        firewall_btn.clicked.connect(self.deploy_firewall)
        tools_layout.addWidget(firewall_btn)
        
        antivirus_btn = QPushButton("🛡️ Cài Antivirus")
        antivirus_btn.clicked.connect(self.install_antivirus)
        tools_layout.addWidget(antivirus_btn)
        
        update_btn = QPushButton("⚡ Cập nhật Bảo mật")
        update_btn.clicked.connect(self.update_security)
        tools_layout.addWidget(update_btn)
        
        layout.addWidget(tools_group)
        
        # Game controls
        controls_layout = QHBoxLayout()
        
        attack_btn = QPushButton("⚠️ Mô phỏng tấn công")
        attack_btn.clicked.connect(self.simulate_attack)
        controls_layout.addWidget(attack_btn)
        
        start_btn = QPushButton("🎮 Bắt đầu game")
        start_btn.clicked.connect(self.start_game)
        controls_layout.addWidget(start_btn)
        
        reset_btn = QPushButton("🔄 Reset mạng")
        reset_btn.clicked.connect(self.reset_network)
        controls_layout.addWidget(reset_btn)
        
        layout.addLayout(controls_layout)
        
        # Initialize network
        self.create_network()
        
    def create_network(self):
        # Clear existing grid
        for i in reversed(range(self.network_grid.count())):
            self.network_grid.itemAt(i).widget().setParent(None)
            
        self.network_nodes = []
        
        # Create 5x5 grid of nodes
        for row in range(5):
            for col in range(5):
                node_id = row * 5 + col
                button = QPushButton(str(node_id + 1))
                button.setFixedSize(60, 60)
                button.clicked.connect(lambda checked, id=node_id: self.click_node(id))
                
                node = {
                    'id': node_id,
                    'status': 'safe',  # safe, infected, protected
                    'button': button
                }
                
                self.network_nodes.append(node)
                self.network_grid.addWidget(button, row, col)
                
        self.update_display()
        
    def click_node(self, node_id):
        node = self.network_nodes[node_id]
        
        if node['status'] == 'infected':
            # Clean infected node
            node['status'] = 'safe'
            self.game_manager.add_score(20, f"Làm sạch máy tính {node_id + 1}")
            self.game_manager.show_notification(f"Đã làm sạch máy tính {node_id + 1}!")
            
        self.update_display()
        
    def deploy_firewall(self):
        safe_nodes = [n for n in self.network_nodes if n['status'] == 'safe']
        if safe_nodes:
            node = random.choice(safe_nodes)
            node['status'] = 'protected'
            self.game_manager.add_score(10, "Triển khai Firewall")
            self.update_display()
            
    def install_antivirus(self):
        infected_nodes = [n for n in self.network_nodes if n['status'] == 'infected']
        if infected_nodes:
            node = random.choice(infected_nodes)
            node['status'] = 'safe'
            self.game_manager.add_score(25, "Cài Antivirus")
        else:
            safe_nodes = [n for n in self.network_nodes if n['status'] == 'safe']
            if safe_nodes:
                node = random.choice(safe_nodes)
                node['status'] = 'protected'
                self.game_manager.add_score(10, "Cài Antivirus bảo vệ")
        self.update_display()
        
    def update_security(self):
        self.game_manager.add_score(15, "Cập nhật bảo mật")
        self.game_manager.show_notification("Hệ thống bảo mật đã được cập nhật!")
        
    def simulate_attack(self):
        for i in range(3):
            QTimer.singleShot(i * 1000, self.random_attack)
            
    def random_attack(self):
        safe_nodes = [n for n in self.network_nodes if n['status'] == 'safe']
        if safe_nodes:
            target = random.choice(safe_nodes)
            
            # Check for protected neighbors
            neighbors = self.get_neighbors(target['id'])
            protected_neighbors = [n for n in neighbors if self.network_nodes[n]['status'] == 'protected']
            
            if protected_neighbors and random.random() < 0.7:
                # Attack blocked
                self.game_manager.add_score(15, "Chặn tấn công")
                self.game_manager.show_notification(f"Chặn tấn công vào máy {target['id'] + 1}!")
            else:
                # Attack successful
                target['status'] = 'infected'
                self.game_manager.show_notification(f"Máy {target['id'] + 1} bị nhiễm!", error=True)
                
        self.update_display()
        
    def get_neighbors(self, node_id):
        neighbors = []
        row = node_id // 5
        col = node_id % 5
        
        # Check adjacent nodes
        for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
            new_row, new_col = row + dr, col + dc
            if 0 <= new_row < 5 and 0 <= new_col < 5:
                neighbors.append(new_row * 5 + new_col)
                
        return neighbors
        
    def start_game(self):
        self.game_active = True
        self.attack_timer = QTimer()
        self.attack_timer.timeout.connect(self.random_attack)
        self.attack_timer.start(3000)  # Attack every 3 seconds
        
    def reset_network(self):
        if hasattr(self, 'attack_timer'):
            self.attack_timer.stop()
        self.game_active = False
        self.create_network()
        
    def update_display(self):
        safe_count = infected_count = protected_count = 0
        
        for node in self.network_nodes:
            button = node['button']
            
            if node['status'] == 'safe':
                button.setStyleSheet("background-color: #28a745; color: white;")
                safe_count += 1
            elif node['status'] == 'infected':
                button.setStyleSheet("background-color: #dc3545; color: white; animation: pulse 1s infinite;")
                infected_count += 1
            elif node['status'] == 'protected':
                button.setStyleSheet("background-color: #007bff; color: white;")
                protected_count += 1
                
        self.safe_label.setText(f"🟢 An toàn: {safe_count}")
        self.infected_label.setText(f"🔴 Bị nhiễm: {infected_count}")
        self.protected_label.setText(f"🛡️ Được bảo vệ: {protected_count}")

class BankSecurityGame(QMainWindow):
    """Game bảo mật ngân hàng chính"""
    
    def __init__(self):
        super().__init__()
        self.game_state = {
            'totalScore': 0,
            'currentLevel': 1,
            'completedTransactions': 0,
            'achievements': 0,
            'streak': 0,
            'currentAESKey': '',
            'currentOTP': '',
            'transactionHistory': []
        }
        
        self.init_ui()
        self.load_stylesheet()
        self.load_game_state()
        
    def init_ui(self):
        """Khởi tạo giao diện người dùng"""
        self.setWindowTitle("🏦 SecureBank Pro - Game Bảo mật Ngân hàng")
        self.setMinimumSize(1024, 700)

        
        # Central widget với background
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Background
        self.background = AnimatedBackground(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header_frame = self.create_header()
        main_layout.addWidget(header_frame)
        
        # Stats panel
        self.stats_widget = GameStatsWidget()
        main_layout.addWidget(self.stats_widget)
        
        # Tab widget for different games
        self.tab_widget = QTabWidget()
        self.setup_tabs()
        main_layout.addWidget(self.tab_widget)
        
        # Update stats display
        self.update_stats_display()
        
    def create_header(self):
        """Tạo header với thông tin game"""
        header_frame = QFrame()
        header_frame.setObjectName("GameHeader")
        header_frame.setFixedHeight(120)
        
        layout = QVBoxLayout(header_frame)
        
        # Title
        title = QLabel("🏦 SecureBank Pro")
        title.setObjectName("GameTitle")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Game Bảo mật Ngân hàng Chuyên nghiệp với 6 Mini Games")
        subtitle.setObjectName("GameSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        
        return header_frame
        
    def setup_tabs(self):
        """Thiết lập các tab cho mini games"""
        
        # Main banking game
        main_game = self.create_main_game_tab()
        self.tab_widget.addTab(main_game, "🏦 Game Chính")
        
        # Mini games
        password_game = PasswordGameWidget(self)
        self.tab_widget.addTab(password_game, "🔐 Mật Khẩu")
        
        crypto_puzzle = CryptoPuzzleWidget(self)
        self.tab_widget.addTab(crypto_puzzle, "🧩 Crypto Puzzle")
        
        hash_race = HashRaceWidget(self)
        self.tab_widget.addTab(hash_race, "⚡ Hash Race")
        
        network_security = NetworkSecurityWidget(self)
        self.tab_widget.addTab(network_security, "🌐 Bảo Mật Mạng")
        
    def create_main_game_tab(self):
        """Tạo tab game chính"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Sender panel
        sender_panel = self.create_sender_panel()
        layout.addWidget(sender_panel)
        
        # Receiver panel  
        receiver_panel = self.create_receiver_panel()
        layout.addWidget(receiver_panel)
        
        # Tools panel
        tools_panel = self.create_tools_panel()
        layout.addWidget(tools_panel)
        
        return widget
        
    def create_sender_panel(self):
        """Tạo panel bên gửi"""
        group = QGroupBox("🏦 Bên Gửi (Ngân Hàng)")
        layout = QVBoxLayout(group)
        
        # AES Key
        layout.addWidget(QLabel("🔑 Khóa AES (256-bit)"))
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setReadOnly(True)
        layout.addWidget(self.aes_key_input)
        
        generate_key_btn = QPushButton("🔑 Tạo khóa AES")
        generate_key_btn.clicked.connect(self.generate_aes_key)
        layout.addWidget(generate_key_btn)
        
        # Sender account
        layout.addWidget(QLabel("💳 Số tài khoản người gửi"))
        self.sender_account = QLineEdit()
        self.sender_account.setPlaceholderText("VD: 1234567890123")
        layout.addWidget(self.sender_account)
        
        # Receiver account  
        layout.addWidget(QLabel("💳 Số tài khoản người nhận"))
        self.receiver_account = QLineEdit()
        self.receiver_account.setPlaceholderText("VD: 9876543210987")
        layout.addWidget(self.receiver_account)
        
        # Amount
        layout.addWidget(QLabel("💰 Số tiền (VND)"))
        self.amount_input = QLineEdit()
        self.amount_input.setPlaceholderText("VD: 1000000")
        layout.addWidget(self.amount_input)
        
        # Description
        layout.addWidget(QLabel("📝 Nội dung chuyển khoản"))
        self.description_input = QLineEdit()
        self.description_input.setPlaceholderText("VD: Thanh toán hóa đơn")
        layout.addWidget(self.description_input)
        
        # Encrypted data
        layout.addWidget(QLabel("🔒 Dữ liệu đã mã hóa"))
        self.encrypted_data = QTextEdit()
        self.encrypted_data.setMaximumHeight(100)
        self.encrypted_data.setReadOnly(True)
        layout.addWidget(self.encrypted_data)
        
        # Buttons
        encrypt_btn = QPushButton("🔒 Mã hóa dữ liệu")
        encrypt_btn.clicked.connect(self.encrypt_transaction)
        layout.addWidget(encrypt_btn)
        
        send_btn = QPushButton("📨 Gửi giao dịch")
        send_btn.clicked.connect(self.send_transaction)
        layout.addWidget(send_btn)
        
        return group
        
    def create_receiver_panel(self):
        """Tạo panel bên nhận"""
        group = QGroupBox("🏪 Bên Nhận (Merchant)")
        layout = QVBoxLayout(group)
        
        # Decrypt key
        layout.addWidget(QLabel("🔑 Khóa giải mã AES"))
        self.decrypt_key = QLineEdit()
        self.decrypt_key.setPlaceholderText("Nhập khóa để giải mã...")
        layout.addWidget(self.decrypt_key)
        
        # Received data
        layout.addWidget(QLabel("📨 Dữ liệu nhận được"))
        self.received_data = QTextEdit()
        self.received_data.setMaximumHeight(100)
        self.received_data.setReadOnly(True)
        layout.addWidget(self.received_data)
        
        # Decrypted data
        layout.addWidget(QLabel("🔓 Dữ liệu đã giải mã"))
        self.decrypted_data = QTextEdit()
        self.decrypted_data.setMaximumHeight(120)
        self.decrypted_data.setReadOnly(True)
        layout.addWidget(self.decrypted_data)
        
        # OTP section
        otp_layout = QHBoxLayout()
        layout.addWidget(QLabel("📱 Mã OTP (6 chữ số)"))
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Nhập mã OTP...")
        self.otp_input.setMaxLength(6)
        otp_layout.addWidget(self.otp_input)
        
        generate_otp_btn = QPushButton("📱 Tạo OTP")
        generate_otp_btn.clicked.connect(self.generate_otp)
        otp_layout.addWidget(generate_otp_btn)
        
        layout.addLayout(otp_layout)
        
        self.otp_display = QLabel()
        self.otp_display.setStyleSheet("color: #FFD700; font-weight: bold; font-size: 14px;")
        layout.addWidget(self.otp_display)
        
        # Buttons
        decrypt_btn = QPushButton("🔓 Giải mã dữ liệu")
        decrypt_btn.clicked.connect(self.decrypt_transaction)
        layout.addWidget(decrypt_btn)
        
        verify_btn = QPushButton("✅ Xác thực giao dịch")
        verify_btn.clicked.connect(self.verify_transaction)
        layout.addWidget(verify_btn)
        
        return group
        
    def create_tools_panel(self):
        """Tạo panel công cụ"""
        group = QGroupBox("🛡️ Công cụ Bảo mật")
        layout = QVBoxLayout(group)
        
        # Hash tool
        layout.addWidget(QLabel("🔨 Tạo Hash SHA-256"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Nhập dữ liệu cần hash...")
        layout.addWidget(self.hash_input)
        
        hash_btn = QPushButton("🔨 Tạo Hash")
        hash_btn.clicked.connect(self.generate_hash)
        layout.addWidget(hash_btn)
        
        self.hash_output = QLineEdit()
        self.hash_output.setReadOnly(True)
        layout.addWidget(self.hash_output)
        
        # Transaction history
        layout.addWidget(QLabel("📊 Lịch sử giao dịch"))
        self.transaction_history = QListWidget()
        self.transaction_history.setMaximumHeight(200)
        layout.addWidget(self.transaction_history)
        
        return group
        
    def load_stylesheet(self):
        """Load stylesheet từ file QSS"""
        try:
            with open('modern_bank_style.qss', 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            # Fallback stylesheet
            self.setStyleSheet("""
                QMainWindow {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                        stop:0 #0f1419, stop:0.5 #1a2332, stop:1 #0f1419);
                    color: #ffffff;
                }
                
                #GameHeader {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(30, 50, 80, 0.9), stop:1 rgba(20, 35, 60, 0.9));
                    border: 2px solid rgba(30, 136, 229, 0.3);
                    border-radius: 15px;
                }
                
                #GameTitle {
                    font-size: 32px;
                    font-weight: bold;
                    color: #FFD700;
                }
                
                #GameSubtitle {
                    font-size: 16px;
                    color: #b0bec5;
                }
                
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #2d5aa0, stop:1 #1e88e5);
                    color: white;
                    border: 2px solid rgba(255, 255, 255, 0.1);
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #3d6bb0, stop:1 #2e98f5);
                }
                
                QLineEdit, QTextEdit {
                    background: rgba(40, 60, 90, 0.8);
                    border: 2px solid rgba(30, 136, 229, 0.3);
                    border-radius: 8px;
                    padding: 8px;
                    color: white;
                }
                
                QLineEdit:focus, QTextEdit:focus {
                    border-color: #1e88e5;
                }
                
                QGroupBox {
                    font-weight: bold;
                    border: 2px solid rgba(30, 136, 229, 0.3);
                    border-radius: 8px;
                    margin-top: 10px;
                    padding-top: 10px;
                }
                
                QGroupBox::title {
                    color: #1e88e5;
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px 0 5px;
                }
                
                #StatCard {
                    background: rgba(30, 50, 80, 0.9);
                    border: 2px solid rgba(30, 136, 229, 0.3);
                    border-radius: 10px;
                    padding: 10px;
                }
            """)
    
    # Game logic methods
    def generate_aes_key(self):
        """Tạo khóa AES mới"""
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        self.game_state['currentAESKey'] = key
        self.aes_key_input.setText(key)
        self.add_score(10, "Tạo khóa AES thành công")
        
    def encrypt_transaction(self):
        """Mã hóa giao dịch"""
        sender = self.sender_account.text()
        receiver = self.receiver_account.text()
        amount = self.amount_input.text()
        description = self.description_input.text()
        key = self.aes_key_input.text()
        
        if not all([sender, receiver, amount, description, key]):
            self.show_notification("Vui lòng điền đầy đủ thông tin!", error=True)
            return
            
        # Validate inputs
        if not sender.isdigit() or len(sender) < 9:
            self.show_notification("Số tài khoản người gửi không hợp lệ!", error=True)
            return
            
        if not receiver.isdigit() or len(receiver) < 9:
            self.show_notification("Số tài khoản người nhận không hợp lệ!", error=True)
            return
            
        try:
            amount_val = int(amount)
            if amount_val < 1000:
                self.show_notification("Số tiền tối thiểu là 1,000 VND!", error=True)
                return
        except ValueError:
            self.show_notification("Số tiền không hợp lệ!", error=True)
            return
            
        # Create transaction data
        transaction_data = {
            'sender': sender,
            'receiver': receiver,
            'amount': amount_val,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            encrypted = encrypt_aes(json.dumps(transaction_data), key)
            self.encrypted_data.setText(encrypted)
            self.add_score(20, "Mã hóa giao dịch thành công")
            self.show_notification("Dữ liệu đã được mã hóa thành công!")
        except Exception as e:
            self.show_notification(f"Lỗi mã hóa: {str(e)}", error=True)
            
    def send_transaction(self):
        """Gửi giao dịch"""
        encrypted = self.encrypted_data.toPlainText()
        if not encrypted:
            self.show_notification("Vui lòng mã hóa dữ liệu trước khi gửi!", error=True)
            return
            
        self.received_data.setText(encrypted)
        self.add_score(15, "Gửi giao dịch thành công")
        self.show_notification("Giao dịch đã được gửi!")
        
    def decrypt_transaction(self):
        """Giải mã giao dịch"""
        encrypted = self.received_data.toPlainText()
        key = self.decrypt_key.text()
        
        if not encrypted or not key:
            self.show_notification("Vui lòng nhập dữ liệu và khóa giải mã!", error=True)
            return
            
        try:
            decrypted = decrypt_aes(encrypted, key)
            self.decrypted_data.setText(decrypted)
            self.add_score(30, "Giải mã thành công")
            self.show_notification("Dữ liệu đã được giải mã thành công!")
        except Exception as e:
            self.show_notification("Lỗi giải mã: Khóa không chính xác!", error=True)
            
    def generate_otp(self):
        """Tạo mã OTP"""
        otp = ''.join(random.choices(string.digits, k=6))
        self.game_state['currentOTP'] = otp
        self.otp_display.setText(f"Mã OTP: {otp}")
        
        # Auto expire after 2 minutes
        QTimer.singleShot(120000, lambda: self.otp_display.setText("Mã OTP đã hết hạn"))
        
        self.show_notification("Mã OTP đã được tạo!")
        
    def verify_transaction(self):
        """Xác thực giao dịch"""
        otp_input = self.otp_input.text()
        decrypted = self.decrypted_data.toPlainText()
        
        if not decrypted:
            self.show_notification("Vui lòng giải mã dữ liệu trước!", error=True)
            return
            
        if not otp_input:
            self.show_notification("Vui lòng nhập mã OTP!", error=True)
            return
            
        if otp_input != self.game_state['currentOTP']:
            self.show_notification("Mã OTP không chính xác!", error=True)
            return
            
        # Transaction successful
        self.game_state['completedTransactions'] += 1
        self.game_state['streak'] += 1
        
        bonus_points = 100 + (self.game_state['currentLevel'] * 20) + (self.game_state['streak'] * 10)
        self.add_score(bonus_points, f"Hoàn thành giao dịch (Level {self.game_state['currentLevel']})")
        
        # Add to history
        transaction = {
            'id': self.game_state['completedTransactions'],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'data': decrypted,
            'level': self.game_state['currentLevel']
        }
        self.game_state['transactionHistory'].append(transaction)
        self.update_transaction_history()
        
        # Level up check
        if self.game_state['completedTransactions'] % 5 == 0:
            self.level_up()
            
        self.show_notification("🎉 Giao dịch hoàn thành thành công!")
        
        # Reset form
        QTimer.singleShot(2000, self.reset_transaction_form)
        
    def level_up(self):
        """Lên cấp"""
        self.game_state['currentLevel'] += 1
        self.game_state['achievements'] += 1
        self.add_score(self.game_state['currentLevel'] * 50, f"Lên cấp {self.game_state['currentLevel']}!")
        self.show_notification(f"🆙 Chúc mừng! Bạn đã lên Level {self.game_state['currentLevel']}!")
        
    def reset_transaction_form(self):
        """Reset form giao dịch"""
        self.sender_account.clear()
        self.receiver_account.clear()
        self.amount_input.clear()
        self.description_input.clear()
        self.encrypted_data.clear()
        self.received_data.clear()
        self.decrypted_data.clear()
        self.decrypt_key.clear()
        self.otp_input.clear()
        self.otp_display.clear()
        
        # Generate new AES key
        self.generate_aes_key()
        
    def generate_hash(self):
        """Tạo hash SHA-256"""
        input_text = self.hash_input.text()
        if not input_text:
            self.show_notification("Vui lòng nhập dữ liệu để hash!", error=True)
            return
            
        hash_result = create_hash(input_text)
        self.hash_output.setText(hash_result)
        self.add_score(5, "Tạo hash thành công")
        self.show_notification("Hash đã được tạo!")
        
    def update_transaction_history(self):
        """Cập nhật lịch sử giao dịch"""
        self.transaction_history.clear()
        
        for transaction in self.game_state['transactionHistory'][-10:]:  # Show last 10
            item_text = f"Giao dịch #{transaction['id']} - Level {transaction['level']} ({transaction['timestamp']})"
            self.transaction_history.addItem(item_text)
            
    def add_score(self, points, reason=""):
        """Thêm điểm"""
        self.game_state['totalScore'] += points
        self.update_stats_display()
        self.show_notification(f"+{points} điểm! {reason}")
        self.save_game_state()
        
    def update_stats_display(self):
        """Cập nhật hiển thị thống kê"""
        self.stats_widget.update_stats(self.game_state)
        
    def show_notification(self, message, error=False):
        """Hiển thị thông báo"""
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Thông báo")
        msg_box.setText(message)
        
        if error:
            msg_box.setIcon(QMessageBox.Critical)
        else:
            msg_box.setIcon(QMessageBox.Information)
            
        msg_box.exec()
        
    def save_game_state(self):
        """Lưu trạng thái game"""
        try:
            with open('game_save.json', 'w', encoding='utf-8') as f:
                json.dump(self.game_state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving game state: {e}")
            
    def load_game_state(self):
        """Load trạng thái game"""
        try:
            if os.path.exists('game_save.json'):
                with open('game_save.json', 'r', encoding='utf-8') as f:
                    saved_state = json.load(f)
                    self.game_state.update(saved_state)
                    self.update_stats_display()
                    self.update_transaction_history()
        except Exception as e:
            print(f"Error loading game state: {e}")

def main():
    """Hàm chính"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("SecureBank Pro")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("SecureBank Team")
    
    # Create and show main window
    game = BankSecurityGame()
    game.show()
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main()