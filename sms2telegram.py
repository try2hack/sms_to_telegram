"""
SMS Service - Reads SMS from Huawei modems and forwards to Telegram
OTP-only mode with option to skip regular messages
"""

import serial
import serial.tools.list_ports
import time
import re
import requests
import threading
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from queue import Queue
from dataclasses import dataclass
from enum import Enum

# ==================== Configuration ====================
@dataclass
class Config:
    """Application configuration"""
    TELEGRAM_BOT_TOKEN: str = "xxx"
    TELEGRAM_CHAT_ID: str = "xxx"
    SERIAL_BAUDRATE: int = 115200
    SERIAL_TIMEOUT: int = 5
    USSD_DELAY: int = 10
    NETWORK_SEARCH_DELAY: int = 15
    DEBUG_ENABLED: bool = False
    BATCH_TIMEOUT: int = 15
    TARGET_DEVICE_NAME: str = "HUAWEI Mobile Connect - 3G PC UI Interface"
    OTP_ONLY_MODE: bool = True  # ตั้งค่า True = ส่งเฉพาะ OTP, False = ส่งทุกข้อความ

# ==================== Constants ====================
class Operator(Enum):
    DTAC = "dtac"
    AIS = "ais"
    TRUE = "true"

USSD_CODES = {
    Operator.DTAC: b'AT+CUSD=1,"*102#",15\r\n',
    Operator.AIS: b'AT+CUSD=1,"*545#",15\r\n',
    Operator.TRUE: b'AT+CUSD=1,"*933#",15\r\n'
}

OPERATOR_MAPPING = {
    "dtac": Operator.DTAC, "happy": Operator.DTAC,
    "ais": Operator.AIS,
    "true": Operator.TRUE, "truemove": Operator.TRUE, "truemove h": Operator.TRUE
}

# ==================== Logging Setup ====================
def setup_logger(debug: bool) -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S")
    
    file_handler = logging.FileHandler('sms_service.log', encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(lambda r: r.msg.encode(sys.stdout.encoding or 'utf-8', errors='ignore'))
    logger.addHandler(console_handler)
    
    return logger

# ==================== Data Classes ====================
@dataclass
class SMSMessage:
    sender: str
    timestamp: str
    message: str
    phone_number: Optional[str] = None
    sequence: Optional[int] = None

# ==================== OTP Extractor ====================
class OTPExtractor:
    """Extract OTP codes from SMS messages"""
    
    OTP_PATTERNS = [
        r'G-(\d{6})',                              # Google
        r'<#>\s*(\d{4,8})',                        # Facebook
        r'Please enter (\d{4,8}) into LINE',       # LINE
        r'認証番号[：:\s]*(\d{4,8})',               # Japanese
        r'(?:รหัส|โค้ด)(?:\s*OTP|ยืนยัน|ตรวจสอบ)?[\s:：]*(\d{4,8})',  # Thai
        r'(?:verification\s+code|OTP|code)[\s:：]*(\d{4,8})',         # English
        r'Your\s+(?:verification\s+)?code\s+is\s*(\d{4,8})',
        r'\b(\d{3}[-\s]\d{3})\b',                 # Format XXX-XXX
        r'\b(\d{2}[-\s]\d{2}[-\s]\d{2})\b',       # Format XX-XX-XX
        r'\b(\d{4,8})\b',                          # Standalone 4-8 digits
    ]
    
    @classmethod
    def extract_otp(cls, message: str) -> Tuple[str, bool]:
        """Extract OTP from SMS. Returns (text, is_otp)"""
        for pattern in cls.OTP_PATTERNS:
            matches = re.findall(pattern, message, re.IGNORECASE)
            if matches:
                otp = re.sub(r'[-\s]', '', matches[0])
                if otp.isdigit() and 4 <= len(otp) <= 8:
                    return otp, True
        
        # Not OTP - return shortened message
        return message[:50] + "..." if len(message) > 50 else message, False

# ==================== Decoders ====================
class TextDecoder:
    @staticmethod
    def decode_hex_text(text: str) -> str:
        """Decode hex-encoded text to UTF-16"""
        if re.fullmatch(r'[0-9A-Fa-f]+', text) and len(text) >= 4 and len(text) % 2 == 0:
            try:
                return bytes.fromhex(text).decode('utf-16-be')
            except:
                pass
        return text
    
    @staticmethod
    def extract_phone_number(text: str) -> str:
        """Extract phone number from text"""
        for pattern in [r'(\+66\d{8,9})', r'(0\d{9})']:
            match = re.search(pattern, text)
            if match:
                return match.group(0)
        
        digits = re.sub(r'\D+', '', text)
        if len(digits) >= 10:
            return '0' + digits[1:10]
        return "ไม่พบเบอร์"

# ==================== Services ====================
class TelegramService:
    """Telegram notification service"""
    
    def __init__(self, bot_token: str, chat_id: str, logger: logging.Logger):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.logger = logger
        self.api_url = f"https://api.telegram.org/bot{bot_token}"
    
    def send(self, message: str) -> bool:
        """Send message to Telegram"""
        try:
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": message},
                timeout=5
            )
            if response.status_code == 200:
                self.logger.info(f"Telegram sent: {message[:50]}...")
                return True
            self.logger.error(f"Telegram failed: {response.text}")
        except Exception as e:
            self.logger.error(f"Telegram error: {e}")
        return False

# ==================== AT Commands ====================
class ATCommand:
    TEST = b'AT\r\n'
    INIT = b'AT+CMGF=1;+CNMI=2,1,0,0,0;+CMEE=2;^USSDMODE=0;+CUSD=1\r\n'
    DELETE_ALL_SMS = b'AT+CMGD=1,4\r\n'
    GET_OPERATOR = b'AT+COPS?\r\n'
    CHECK_REGISTRATION = b'AT+CREG?\r\n'
    
    @staticmethod
    def read_sms(index: int) -> bytes:
        return f'AT+CMGR={index};+CMGD={index}\r\n'.encode()

# ==================== Modem Management ====================
class Modem:
    """Represents a single modem connection"""
    
    def __init__(self, port: str, config: Config, logger: logging.Logger):
        self.port = port
        self.config = config
        self.logger = logger
        self.serial: Optional[serial.Serial] = None
        self.phone_number: Optional[str] = None
        self.operator: Optional[Operator] = None
        self.initialized = False
        self.sequence: Optional[int] = None
        self._lock = threading.Lock()
    
    def connect(self) -> bool:
        """Establish serial connection"""
        with self._lock:
            try:
                if self.serial and self.serial.is_open:
                    self.serial.close()
                self.serial = serial.Serial(self.port, self.config.SERIAL_BAUDRATE, timeout=self.config.SERIAL_TIMEOUT)
                self.logger.debug(f"Connected to {self.port}")
                return True
            except serial.SerialException as e:
                if "PermissionError(13" not in str(e):
                    self.logger.error(f"Failed to connect to {self.port}: {e}")
                return False
    
    def close(self):
        """Close serial connection"""
        with self._lock:
            if self.serial and self.serial.is_open:
                try:
                    self.serial.close()
                    self.logger.debug(f"Closed {self.port}")
                except Exception as e:
                    self.logger.error(f"Error closing {self.port}: {e}")
    
    def send_command(self, command: bytes, delay: float = 0.5) -> str:
        """Send AT command and return response"""
        try:
            if not self.serial or not self.serial.is_open:
                return ""
            self.serial.write(command)
            self.logger.debug(f"Sent to {self.port}: {command}")
            time.sleep(delay)
            response = self.serial.read(self.serial.in_waiting).decode('ascii', errors='ignore')
            self.logger.debug(f"Response from {self.port}: {response}")
            return response
        except serial.SerialException as e:
            if "PermissionError(13" not in str(e):
                self.logger.error(f"Command failed on {self.port}: {e}")
            return ""
    
    def initialize(self) -> bool:
        """Initialize modem with required settings"""
        if not self.connect():
            return False
        try:
            if "OK" not in self.send_command(ATCommand.TEST):
                self.logger.error(f"Modem {self.port} not responding")
                return False
            self.send_command(ATCommand.INIT, delay=1.0)
            self.initialized = True
            self.logger.info(f"Modem {self.port} initialized")
            return True
        finally:
            self.close()
    
    def delete_all_sms(self):
        """Delete all stored SMS messages"""
        if self.connect():
            try:
                self.send_command(ATCommand.DELETE_ALL_SMS, delay=2.0)
                self.logger.info(f"Deleted all SMS on {self.port}")
            finally:
                self.close()
    
    def get_operator(self) -> Optional[Operator]:
        """Get network operator"""
        if self.operator:
            return self.operator
        
        if not self.connect():
            return None
        
        try:
            time.sleep(self.config.NETWORK_SEARCH_DELAY)
            response = self.send_command(ATCommand.GET_OPERATOR)
            match = re.search(r'\+COPS: \d+,\d+,"([^"]+)",\d+', response)
            
            if match:
                operator_name = match.group(1).lower()
                for key, op in OPERATOR_MAPPING.items():
                    if key in operator_name:
                        self.operator = op
                        self.logger.info(f"Found operator: {op.value} on {self.port}")
                        return op
            self.logger.warning(f"No operator found on {self.port}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting operator: {e}")
            return None
        finally:
            self.close()
    
    def check_ussd(self, operator: Operator) -> Optional[str]:
        """Check phone number via USSD"""
        if operator not in USSD_CODES:
            return None
        
        self.logger.info(f"Checking {operator.value} number on {self.port}")
        
        if not self.connect():
            return None
        
        try:
            response = self.send_command(USSD_CODES[operator], delay=self.config.USSD_DELAY)
            match = re.search(r'\+CUSD:\s*\d+,"([^"]+)",?', response)
            if match:
                decoded = TextDecoder.decode_hex_text(match.group(1))
                phone = TextDecoder.extract_phone_number(decoded)
                if phone != "ไม่พบเบอร์":
                    self.logger.info(f"Found number {phone} on {self.port}")
                    return phone
            return None
        finally:
            self.close()
    
    def get_phone_number(self) -> Optional[str]:
        """Get phone number for this modem"""
        if not self.connect():
            return None
        
        try:
            response = self.send_command(ATCommand.CHECK_REGISTRATION)
            if "+CREG: 0,0" in response:
                self.logger.warning(f"Modem {self.port} not registered")
                return None
            
            self.close()
            
            # Try with detected operator first
            operator = self.get_operator()
            if operator:
                phone = self.check_ussd(operator)
                if phone:
                    self.phone_number = phone
                    return phone
            
            # Fallback: try all operators
            for operator in Operator:
                phone = self.check_ussd(operator)
                if phone:
                    self.operator = operator
                    self.phone_number = phone
                    self.logger.info(f"Fallback found number {phone} using {operator.value} on {self.port}")
                    return phone
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting phone number: {e}")
            return None
        finally:
            self.close()

# ==================== SMS Processing ====================
class SMSReader:
    """Handles SMS reading from modem"""
    
    def __init__(self, modem: Modem, logger: logging.Logger):
        self.modem = modem
        self.logger = logger
    
    def read_loop(self, stop_event: threading.Event, callback):
        """Main SMS reading loop"""
        self.logger.info(f"Starting SMS reader for {self.modem.port}")
        
        if not self.modem.connect():
            return
        
        try:
            while not stop_event.is_set():
                response = self.modem.send_command(b'', delay=0.5)
                
                if '+CMTI:' in response:
                    match = re.search(r'\+CMTI:\s*"SM",(\d+)', response)
                    if match:
                        index = match.group(1)
                        self.logger.info(f"New SMS at index {index}")
                        sms_response = self.modem.send_command(ATCommand.read_sms(int(index)), delay=1.0)
                        sms = self._parse_sms(sms_response)
                        if sms:
                            callback(sms)
                
                time.sleep(0.5)
        except Exception as e:
            self.logger.error(f"SMS reader error: {e}")
        finally:
            self.modem.close()
            self.logger.info(f"SMS reader stopped for {self.modem.port}")
    
    def _parse_sms(self, response: str) -> Optional[SMSMessage]:
        """Parse SMS from AT command response"""
        lines = response.split('\n')
        
        for i, line in enumerate(lines):
            if '+CMGR:' not in line:
                continue
            
            match = re.match(r'\+CMGR:\s*"[^"]+","([^"]+)",[^,]*,"([^"]+)"', line)
            if match and i + 1 < len(lines):
                return SMSMessage(
                    sender=match.group(1),
                    timestamp=match.group(2),
                    message=TextDecoder.decode_hex_text(lines[i + 1].strip()),
                    phone_number=self.modem.phone_number,
                    sequence=self.modem.sequence
                )
        return None

class SMSBatchProcessor:
    """Handles batching and sending SMS messages with OTP extraction"""
    
    def __init__(self, telegram: TelegramService, logger: logging.Logger, 
                 batch_timeout: int, otp_only_mode: bool):
        self.telegram = telegram
        self.logger = logger
        self.batch_timeout = batch_timeout
        self.otp_only_mode = otp_only_mode
        self.queue = Queue()
    
    def add_message(self, sms: SMSMessage):
        """Add SMS to batch queue with OTP extraction"""
        sequence_str = f" #{sms.sequence}" if sms.sequence else ""
        
        # Extract OTP from message
        text_or_otp, is_otp = OTPExtractor.extract_otp(sms.message)
        
        if is_otp:
            text = f"{sms.phone_number or 'Unknown'}{sequence_str}: {text_or_otp}"
            self.logger.info(f"OTP extracted: {text_or_otp} from {sms.sender}")
            self.queue.put((sms.phone_number, sms.sequence, text, True))
        else:
            # Regular message
            if not self.otp_only_mode:
                text = f"{sms.phone_number or 'Unknown'}{sequence_str}: {text_or_otp}"
                self.logger.info(f"Regular message: {text_or_otp[:30]}...")
                self.queue.put((sms.phone_number, sms.sequence, text, False))
            else:
                self.logger.info(f"Skipped regular message from {sms.sender}: {text_or_otp[:30]}...")
    
    def process_batch(self, active_modems: Dict[str, Modem]):
        """Process and send batched messages"""
        self.logger.info("Processing SMS batch")
        
        messages_by_sequence = {}
        received_numbers = set()
        has_otp = False
        start_time = time.time()
        
        # Count active modems
        total_modems = sum(1 for m in active_modems.values() 
                          if m.phone_number and m.phone_number != "ไม่พบเบอร์")
        
        # Collect messages
        while (len(received_numbers) < total_modems and 
               (time.time() - start_time) < self.batch_timeout):
            if not self.queue.empty():
                phone, seq, text, is_otp = self.queue.get()
                if phone and seq is not None:
                    messages_by_sequence[seq] = text
                    received_numbers.add(phone)
                    if is_otp:
                        has_otp = True
            time.sleep(0.1)
        
        # Get remaining
        while not self.queue.empty():
            phone, seq, text, is_otp = self.queue.get()
            if phone and seq is not None:
                messages_by_sequence[seq] = text
                received_numbers.add(phone)
                if is_otp:
                    has_otp = True
        
        # Add "No SMS" for non-receiving modems (only if we have OTP)
        if has_otp or not self.otp_only_mode:
            for modem in active_modems.values():
                if (modem.phone_number and 
                    modem.phone_number not in received_numbers and
                    modem.phone_number != "ไม่พบเบอร์" and
                    modem.sequence is not None):
                    seq_str = f" #{modem.sequence}"
                    messages_by_sequence[modem.sequence] = f"{modem.phone_number}{seq_str}: 💤"
        
        # Send batch
        if messages_by_sequence:
            sorted_messages = [messages_by_sequence[seq] 
                             for seq in sorted(messages_by_sequence.keys())]
            self.telegram.send("\n".join(sorted_messages))
    
    def run_processor(self, active_modems: Dict[str, Modem]):
        """Main batch processor thread"""
        self.logger.info(f"Starting SMS batch processor (OTP only mode: {self.otp_only_mode})")
        
        while True:
            while self.queue.empty():
                time.sleep(0.1)
            self.process_batch(active_modems)

# ==================== Main Application ====================
class SMSService:
    """Main SMS service application"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger(config.DEBUG_ENABLED)
        self.telegram = TelegramService(config.TELEGRAM_BOT_TOKEN, config.TELEGRAM_CHAT_ID, self.logger)
        self.active_modems = {}
        self.reader_threads = {}
        self.batch_processor = SMSBatchProcessor(
            self.telegram, self.logger, config.BATCH_TIMEOUT, config.OTP_ONLY_MODE
        )
    
    def setup_modem(self, modem: Modem):
        """Initialize and setup a single modem"""
        try:
            if modem.initialize():
                modem.phone_number = modem.get_phone_number()
                if modem.initialized:
                    modem.delete_all_sms()
            else:
                modem.initialized = False
        except Exception as e:
            self.logger.error(f"Failed to setup modem {modem.port}: {e}")
            modem.initialized = False
    
    def start_sms_reader(self, modem: Modem):
        """Start SMS reader thread for modem"""
        reader = SMSReader(modem, self.logger)
        stop_event = threading.Event()
        
        thread = threading.Thread(
            target=reader.read_loop,
            args=(stop_event, self.batch_processor.add_message)
        )
        thread.daemon = True
        thread.start()
        
        self.reader_threads[modem.port] = (thread, stop_event)
    
    def send_startup_message(self):
        """Send service startup notification"""
        mode = "OTP Only" if self.config.OTP_ONLY_MODE else "All Messages"
        messages = [f"📡 SMS Service Started ({mode})"]
        
        for modem in sorted(self.active_modems.values(), key=lambda m: m.sequence or 0):
            if modem.sequence is not None:
                phone = modem.phone_number or "Not responding"
                messages.append(f"{phone} #{modem.sequence}")
        
        self.telegram.send("\n".join(messages))
    
    def run(self):
        """Main service execution"""
        mode = "OTP Only" if self.config.OTP_ONLY_MODE else "All Messages"
        print(f"[{datetime.now().strftime('%H:%M:%S')}]: 🚗 Starting SMS Service ({mode})...")
        self.logger.info(f"SMS Service starting ({mode})...")
        
        # Discover modems
        ports = [p.device for p in serial.tools.list_ports.comports() 
                if self.config.TARGET_DEVICE_NAME.lower() in p.description.lower()]
        
        if not ports:
            print(f"[{datetime.now().strftime('%H:%M:%S')}]: ❌ No Huawei modems found")
            self.logger.error("No modems found")
            return
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}]: Found {len(ports)} modem(s): {ports}")
        
        # Initialize modems
        setup_threads = []
        for index, port in enumerate(ports, 1):
            modem = Modem(port, self.config, self.logger)
            modem.sequence = index
            self.active_modems[port] = modem
            
            thread = threading.Thread(target=self.setup_modem, args=(modem,))
            thread.daemon = True
            setup_threads.append(thread)
            thread.start()
        
        # Wait for initialization
        for thread in setup_threads:
            thread.join()
        
        # Start SMS readers
        for modem in self.active_modems.values():
            if modem.initialized:
                seq_str = f" #{modem.sequence}" if modem.sequence else ""
                phone_str = modem.phone_number or "No number"
                print(f"[{datetime.now().strftime('%H:%M:%S')}]: 🟢 Modem ready: {modem.port} ({phone_str}{seq_str})")
                self.start_sms_reader(modem)
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}]: 🔴 Modem not responding: {modem.port}")
        
        # Send startup notification
        self.send_startup_message()
        
        # Start batch processor
        batch_thread = threading.Thread(
            target=self.batch_processor.run_processor,
            args=(self.active_modems,)
        )
        batch_thread.daemon = True
        batch_thread.start()
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}]: ✅ SMS Service running ({mode}). Press Ctrl+C to stop.")
        self.logger.info(f"SMS Service is now running ({mode})")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()
    
    def shutdown(self):
        """Graceful shutdown"""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}]: 🛑 Stopping SMS Service...")
        self.logger.info("SMS Service stopping...")
        
        # Stop readers
        for port, (thread, stop_event) in self.reader_threads.items():
            self.logger.info(f"Stopping thread for {port}")
            stop_event.set()
            thread.join(timeout=3)
            self.logger.info(f"Thread for {port} {'stopped' if not thread.is_alive() else 'did not stop cleanly'}")
        
        # Close modems
        for modem in self.active_modems.values():
            modem.close()
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}]: 👋 SMS Service stopped")
        self.logger.info("SMS Service stopped")

# ==================== Entry Point ====================
def main():
    """Application entry point"""
    config = Config()
    service = SMSService(config)
    service.run()

if __name__ == "__main__":
    main()
