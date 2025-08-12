import hashlib
import sys
import re
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QMessageBox, QProgressBar, QTextEdit, QHBoxLayout
)
from PyQt6.QtCore import (
    Qt, QThreadPool, QRunnable, pyqtSignal, QObject, QEvent,
    QPropertyAnimation, QEasingCurve, QMutex
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtMultimedia import QSoundEffect
from PyQt6.QtCore import QUrl

# -----------------------------------
SUSPICIOUS_PATTERNS_RAW = [
    # Windows API & hacking related
    r"CreateRemoteThread", r"GetProcAddress", r"VirtualAlloc",
    r"VirtualProtect", r"LoadLibrary", r"WinExec",
    r"OpenProcess", r"WriteProcessMemory", r"ReadProcessMemory",
    r"TerminateProcess", r"AdjustTokenPrivileges",
    r"NtQuerySystemInformation", r"ZwQuerySystemInformation",
    r"SetWindowsHookEx", r"UnhookWindowsHookEx",

    # Command line & PowerShell
    r"cmd\.exe", r"powershell", r"wmic", r"mshta",
    r"rundll32", r"regsvr32", r"schtasks", r"bcdedit",

    # Networking & downloads
    r"socket", r"connect", r"send", r"recv", r"bind", r"listen",
    r"wget\s+http", r"curl\s+http", r"Invoke-WebRequest",
    r"System\.Net\.WebClient", r"FtpWebRequest", r"http[s]?://",

    # Encoding / encryption
    r"base64\s*\-decode", r"Convert\.ToBase64String",
    r"FromBase64String", r"XXTEA", r"AES", r"RC4", r"DES",

    # Keylogging & spying
    r"keylogger", r"GetAsyncKeyState", r"GetForegroundWindow",
    r"SetWindowsHook", r"FindWindow", r"FindWindowEx",

    # Persistence & autorun
    r"RunOnce", r"RunServices", r"CurrentVersion\\Run",
    r"CurrentVersion\\Policies", r"Startup", r"Shell=Explorer\.exe",

    # File operations
    r"CreateFile", r"WriteFile", r"ReadFile", r"DeleteFile",
    r"CopyFile", r"MoveFile", r"SHFileOperation",

    # Process injection
    r"PROCESS_ALL_ACCESS", r"PAGE_EXECUTE_READWRITE",
    r"MEM_COMMIT", r"MEM_RESERVE",

    # Malware terms
    r"brute[-\s]?force", r"exploit", r"backdoor", r"RAT",
    r"trojan", r"malware", r"ransomware",
    r"keygen", r"crack", r"dump", r"payload", r"shellcode",
    r"inject", r"hook", r"rootkit",

    # Privilege escalation
    r"privilege\s*escalation", r"token\s*stealing",
    r"process\s*hollowing",

    # Obfuscation & protection
    r"obfuscate", r"packer", r"polymorphic", r"metamorphic",
    r"anti[-\s]?debug",

    # Plus more generic hacking terms
    r"exploit", r"payload", r"scanner", r"bypass", r"debugger",
    r"dump", r"shell", r"botnet", r"command\s*and\s*control",
    r"command\s*control", r"C2", r"persistence", r"exfiltrate",
    r"encryption", r"decryption", r"spyware", r"trojanhorse",
    r"payload", r"exploitkit", r"cryptominer", r"mining",
    r"malicious", r"dangerous", r"attack", r"threat", r"virus",
    r"worm", r"spy", r"infect", r"infected", r"compromise",
    r"shellcode", r"buffer\s*overflow", r"SQL\s*injection",
    r"cross[-\s]?site\s*scripting", r"XSS", r"zero-day",
    r"zero\s*day", r"0day", r"root", r"honeypot", r"honeynet",
    r"phishing", r"spy", r"skimmer", r"trojan",
    r"packet\s*sniffer", r"key\s*exchange", r"man-in-the-middle",
    r"MITM", r"dos", r"ddos", r"denial\s*of\s*service",
    r"ransom", r"fraud", r"credential\s*stealing",
    r"password\s*stealing", r"data\s*breach", r"data\s*leak",
    r"APT", r"advanced\s*persistent\s*threat", r"rootkit",
    r"bot", r"zombie", r"command\s*execution", r"remote\s*access",
    r"backdoor", r"trojan", r"virus", r"worm", r"spyware", r"adware",
    r"exploit", r"honeypot", r"phishing", r"malspam", r"dropper",
    r"script", r"macro", r"exploit\s*kit", r"memory\s*corruption",
    r"heap\s*spraying", r"code\s*injection", r"cross-site\s*scripting",
    r"rce", r"remote\s*code\s*execution",

    # Mining / Cryptomining terms
    r"mining", r"cryptominer", r"coinminer", r"cryptocurrency",
    r"hashrate", r"stratum", r"pool", r"wallet", r"monero",
    r"xmrig", r"gpu_miner", r"cpu_miner", r"silent_miner",
    r"cryptojacking", r"mine", r"miner", r"cryptomining",
    r"cryptocurrency_miner", r"coinhive", r"xmr-stak", r"nicehash",
    r"cudo_miner",
]

SUSPICIOUS_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in SUSPICIOUS_PATTERNS_RAW]

hash_cache = {}
cache_mutex = QMutex()


def classify_risk(count: int) -> str:
    if count == 0:
        return "SAFE"
    elif 1 <= count <= 4:
        return "LOW"
    elif 5 <= count <= 9:
        return "MEDIUM"
    elif 10 <= count <= 19:
        return "HIGH"
    else:
        return "CRITICAL"


class ScannerSignals(QObject):
    progress = pyqtSignal(int)
    result = pyqtSignal(str, bool, list)  # filepath, found, details


class FileScanTask(QRunnable):
    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
        self.signals = ScannerSignals()

    def run(self):
        found_patterns = []
        try:
            with open(self.filepath, "rb") as f:
                content_bytes = f.read()
                content = content_bytes.decode(errors="ignore")

            # Check cache first
            filehash = hashlib.sha256(content_bytes).hexdigest()
            cache_mutex.lock()
            cached = hash_cache.get(filehash)
            cache_mutex.unlock()
            if cached is not None:
                # Already scanned, send cached results
                self.signals.result.emit(self.filepath, bool(cached), cached if cached else [])
                self.signals.progress.emit(100)
                return

            total = len(SUSPICIOUS_PATTERNS)
            for i, pattern in enumerate(SUSPICIOUS_PATTERNS, start=1):
                if pattern.search(content):
                    found_patterns.append(pattern.pattern)
                self.signals.progress.emit(int((i / total) * 100))

            results = found_patterns + [f"SHA256: {filehash}"]

            cache_mutex.lock()
            hash_cache[filehash] = found_patterns  # Cache result
            cache_mutex.unlock()

            self.signals.result.emit(self.filepath, len(found_patterns) > 0, results)
            self.signals.progress.emit(100)
        except Exception as e:
            self.signals.result.emit(self.filepath, None, [str(e)])
            self.signals.progress.emit(100)


class TrojanScannerUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TrojanHunter Pro Ultimate R3")
        self.setWindowIcon(QIcon("iconfile38.ico"))
        self.setGeometry(300, 150, 700, 480)
        self.setAcceptDrops(True)

        self.dark_style = """
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
            }
            QLabel {
                color: #f5f5f5;
            }
            QPushButton {
                background-color: #0d6efd;
                color: white;
                padding: 12px 28px;
                border-radius: 14px;
                font-weight: 700;
                min-width: 160px;
                max-width: 260px;
                transition: background-color 0.3s ease-in-out;
            }
            QPushButton:hover {
                background-color: #3a81ff;
            }
            QPushButton:pressed {
                background-color: #054ecb;
            }
            QProgressBar {
                background-color: #222222;
                border: 1px solid #444444;
                border-radius: 14px;
                height: 24px;
                text-align: center;
                color: #aaaaaa;
                font-weight: 700;
            }
            QProgressBar::chunk {
                background-color: #3399ff;
                border-radius: 14px;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #333333;
                border-radius: 14px;
                padding: 14px;
                color: #eeeeee;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
            }
        """

        self.light_style = """
            QWidget {
                background-color: #fefefe;
                color: #222222;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
            }
            QLabel {
                color: #222222;
            }
            QPushButton {
                background-color: #007bff;
                color: white;
                padding: 12px 28px;
                border-radius: 14px;
                font-weight: 700;
                min-width: 160px;
                max-width: 260px;
                transition: background-color 0.3s ease-in-out;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #003d80;
            }
            QProgressBar {
                background-color: #e0e0e0;
                border: 1px solid #bbb;
                border-radius: 14px;
                height: 24px;
                text-align: center;
                color: #555555;
                font-weight: 700;
            }
            QProgressBar::chunk {
                background-color: #007bff;
                border-radius: 14px;
            }
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #bbb;
                border-radius: 14px;
                padding: 14px;
                color: #222222;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
            }
        """

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.title = QLabel("🔍 TrojanHunter Pro Ultimate R3 - MAXIMUM Trojan Scanner")
        self.title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.title)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.layout.addWidget(self.log, stretch=1)

        self.progress = QProgressBar()
        self.layout.addWidget(self.progress)

        btn_layout = QHBoxLayout()

        self.scan_btn = QPushButton("Select EXE to Scan")
        self.scan_btn.setToolTip("Select a file to scan for suspicious patterns")
        self.scan_btn.clicked.connect(self.select_file)
        btn_layout.addWidget(self.scan_btn)

        self.scan_folder_btn = QPushButton("Scan Folder")
        self.scan_folder_btn.setToolTip("Scan all .exe files in a folder")
        self.scan_folder_btn.clicked.connect(self.select_folder)
        btn_layout.addWidget(self.scan_folder_btn)

        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.setToolTip("Clear scan logs")
        self.clear_log_btn.clicked.connect(self.log.clear)
        btn_layout.addWidget(self.clear_log_btn)

        self.theme_btn = QPushButton("Toggle Theme")
        self.theme_btn.setToolTip("Switch between dark and light mode")
        self.theme_btn.clicked.connect(self.toggle_theme)
        btn_layout.addWidget(self.theme_btn)

        self.layout.addLayout(btn_layout)

        self.is_dark = True
        self.setStyleSheet(self.dark_style)

        # Sounds
        self.hover_sound = QSoundEffect()
        self.hover_sound.setSource(
            QUrl.fromLocalFile(":/qt-project.org/styles/commonstyle/images/standardbutton-pressed.wav"))
        self.hover_sound.setVolume(0.2)

        self.click_sound = QSoundEffect()
        self.click_sound.setSource(
            QUrl.fromLocalFile(":/qt-project.org/styles/commonstyle/images/standardbutton-pressed.wav"))
        self.click_sound.setVolume(0.3)

        for btn in [self.scan_btn, self.scan_folder_btn, self.clear_log_btn, self.theme_btn]:
            btn.installEventFilter(self)

        self.anim = QPropertyAnimation(self.scan_btn, b"minimumWidth")
        self.anim.setDuration(300)
        self.anim.setStartValue(160)
        self.anim.setKeyValueAt(0.5, 200)
        self.anim.setEndValue(160)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.scan_btn.pressed.connect(lambda: self.anim.start())

        self.threadpool = QThreadPool()
        self.files_to_scan = []
        self.total_files = 0
        self.files_scanned = 0
        self.results_found = 0

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Enter and isinstance(obj, QPushButton):
            if not self.hover_sound.isPlaying():
                self.hover_sound.play()
        elif event.type() == QEvent.Type.MouseButtonPress and isinstance(obj, QPushButton):
            self.click_sound.play()
        return super().eventFilter(obj, event)

    def toggle_theme(self):
        if self.is_dark:
            self.setStyleSheet(self.light_style)
            self.is_dark = False
        else:
            self.setStyleSheet(self.dark_style)
            self.is_dark = True

    def select_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select EXE file", "",
                                                  "Executable Files (*.exe);;All Files (*.*)")
        if filepath:
            self.log.append(f"[Info] Selected file: {filepath}")
            self.files_to_scan = [filepath]
            self.total_files = 1
            self.files_scanned = 0
            self.results_found = 0
            self.progress.setValue(0)
            self.disable_buttons()
            self.start_scanning()

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.log.append(f"[Info] Selected folder: {folder}")
            self.files_to_scan = []
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if file.lower().endswith(".exe"):
                        self.files_to_scan.append(os.path.join(root, file))
            if not self.files_to_scan:
                QMessageBox.information(self, "No EXE files", "No .exe files found in the selected folder.")
                self.log.append("[Info] No .exe files found.\n")
                return
            self.total_files = len(self.files_to_scan)
            self.files_scanned = 0
            self.results_found = 0
            self.progress.setValue(0)
            self.log.append(f"[Batch Scan] {self.total_files} .exe files found. Starting scan...")
            self.disable_buttons()
            self.start_scanning()

    def disable_buttons(self):
        self.scan_btn.setEnabled(False)
        self.scan_folder_btn.setEnabled(False)
        self.clear_log_btn.setEnabled(False)
        self.theme_btn.setEnabled(False)

    def enable_buttons(self):
        self.scan_btn.setEnabled(True)
        self.scan_folder_btn.setEnabled(True)
        self.clear_log_btn.setEnabled(True)
        self.theme_btn.setEnabled(True)

    def start_scanning(self):
        for filepath in self.files_to_scan:
            task = FileScanTask(filepath)
            task.signals.progress.connect(self.update_progress)
            task.signals.result.connect(self.handle_result)
            self.threadpool.start(task)

    def update_progress(self, val):
        current = self.progress.value()
        if val > current:
            self.progress.setValue(val)

    def handle_result(self, filepath, found, details):
        self.files_scanned += 1

        if found is True:
            self.results_found += 1
            self.log.append(f"[ALERT] Suspicious patterns found in: {filepath}")
            for d in details:
                self.log.append(f"  - {d}")
            risk_level = classify_risk(len(details) - 1)
            self.log.append(f"Risk level: {risk_level}\n")

        elif found is False:
            self.log.append(f"[Safe] No suspicious patterns found in: {filepath}\n")

        else:
            self.log.append(f"[Error] Failed to scan {filepath}: {details[0]}\n")

        overall_progress = int((self.files_scanned / self.total_files) * 100)
        self.progress.setValue(overall_progress)

        if self.files_scanned == self.total_files:
            self.progress.setValue(100)
            self.log.append(
                f"\n🔔 Scan complete! Total files scanned: {self.total_files}. Files with suspicious content: {self.results_found}\n")

            if self.results_found == 0:
                QMessageBox.information(self, "Scan Complete",
                                        "No suspicious patterns found in any scanned files. You're safe! ✅")
            else:
                QMessageBox.warning(self, "Scan Complete",
                                    f"Warning: Suspicious patterns detected in {self.results_found} file(s). Please review the log above.")

            self.enable_buttons()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TrojanScannerUI()
    window.show()
    sys.exit(app.exec())