import serial
import serial.tools.list_ports
import time
import re
import requests
import threading
from datetime import datetime
from typing import Optional
import logging
import sys

# Logging Setup
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S")
file_handler = logging.FileHandler('sms_service.log', encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class NoEmojiFilter(logging.Filter):
    def filter(self, record):
        try:
            record.msg.encode(sys.stdout.encoding or 'utf-8')
            return True
        except UnicodeEncodeError:
            return False

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.addFilter(NoEmojiFilter())
logger.addHandler(console_handler)

# Configuration
TELEGRAM_BOT_TOKEN = "xxx"
TELEGRAM_CHAT_ID = "xxx"
CONFIG = {
    "SERIAL_BAUDRATE": 115200,
    "SERIAL_TIMEOUT": 10,
    "HOTPLUG_POLL_INTERVAL": 10,
    "USSD_DELAY": 5,
    "DEBUG_ENABLED": False
}

logger.setLevel(logging.DEBUG if CONFIG["DEBUG_ENABLED"] else logging.INFO)

port_lock = threading.Lock()

# Utility Functions
def decode_ussd(hex_str: str) -> str:
    logger.debug(f"Attempting to decode USSD: {hex_str}")
    if not re.fullmatch(r'[0-9A-Fa-f]+', hex_str) or len(hex_str) < 4 or len(hex_str) % 2 != 0:
        logger.debug(f"Not a valid hex string for USSD, returning as is: {hex_str}")
        return hex_str
    try:
        decoded = bytes.fromhex(hex_str).decode('utf-16-be')
        logger.debug(f"Successfully decoded USSD to: {decoded}")
        return decoded
    except Exception as e:
        logger.error(f"Error decoding USSD: {e}")
        return hex_str

def decode_sms(text: str) -> str:
    logger.debug(f"Attempting to decode SMS: {text}")
    if text.isdigit():
        logger.debug(f"SMS is all digits, returning as is: {text}")
        return text
    if re.fullmatch(r'[0-9A-Fa-f]+', text) and len(text) >= 4 and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode('utf-16-be')
            logger.debug(f"Successfully decoded SMS to: {decoded}")
            return decoded
        except Exception as e:
            logger.error(f"Error decoding SMS: {e}")
            return text
    logger.debug(f"SMS is not HEX, returning as is: {text}")
    return text

def extract_phone_number(decoded: str) -> str:
    logger.debug(f"Extracting phone number from: {decoded}")
    cleaned = re.sub(r'\D+', '', decoded)
    logger.debug(f"Cleaned input: {cleaned}")
    patterns = [
        r'(\+66\d{8,9})',
        r'(0\d{9})',
        r'(\d{10})'
    ]
    for pattern in patterns:
        match = re.search(pattern, decoded)
        if match:
            phone = match.group(0)
            logger.debug(f"Matched phone pattern: {phone}")
            if phone.startswith('0') and len(phone) == 10:
                logger.debug(f"Using phone as is: {phone}")
                return phone
            elif phone.startswith('+66'):
                logger.debug(f"Using phone as is: {phone}")
                return phone
            elif len(phone) == 10:
                phone = '0' + phone[1:]
                logger.debug(f"Converted to: {phone}")
                return phone
    if len(cleaned) >= 10 and cleaned.isdigit():
        phone = '0' + cleaned[1:10]
        logger.debug(f"Using cleaned input as phone: {phone}")
        return phone
    logger.warning(f"ไม่สามารถแยกเบอร์จากข้อความ: {decoded}")
    return "ไม่พบเบอร์"

def send_to_telegram(message: str):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info(f"ส่ง Telegram สำเร็จ: {message[:50]}...")
        else:
            logger.error(f"ส่ง Telegram ล้มเหลว: {response.text}")
    except Exception as e:
        logger.error(f"ส่ง Telegram error: {e}")

def send_sms_to_telegram(sender, timestamp, message, port, phone_number=None):
    text = f"📩 {phone_number or 'ไม่ทราบ'}: {message}"
    send_to_telegram(text)

class Modem:
    def __init__(self, port: str, baudrate: int = CONFIG["SERIAL_BAUDRATE"]):
        self.port = port
        self.baudrate = baudrate
        self.serial = None
        self.phone_number: Optional[str] = None

    def connect(self) -> bool:
        with port_lock:
            try:
                if self.serial and self.serial.is_open:
                    self.serial.close()
                self.serial = serial.Serial(self.port, self.baudrate, timeout=CONFIG["SERIAL_TIMEOUT"])
                logger.debug(f"Connected to port {self.port}")
                return True
            except serial.SerialException as e:
                if "PermissionError(13" in str(e):
                    return False
                logger.error(f"เชื่อมต่อพอร์ต {self.port} ไม่สำเร็จ: {e}")
                return False

    def close(self):
        if self.serial and self.serial.is_open:
            try:
                self.serial.close()
                logger.debug(f"Closed port {self.port}")
            except Exception as e:
                logger.error(f"ปิดพอร์ต {self.port} ล้มเหลว: {e}")

    def send_command(self, command: bytes, delay: float = 1.0) -> str:
        try:
            if not self.serial or not self.serial.is_open:
                logger.error(f"Port {self.port} is not open before sending command")
                return ""
            self.serial.write(command)
            logger.debug(f"Sent command to {self.port}: {command}")
            time.sleep(delay)
            response = self.serial.read(self.serial.in_waiting).decode('ascii', errors='ignore')
            logger.debug(f"Received response from {self.port}: {response}")
            return response
        except serial.SerialException as e:
            if "PermissionError(13" in str(e):
                return ""
            logger.error(f"ส่งคำสั่งที่ {self.port} ล้มเหลว: {e}")
            return ""

def initialize_modem(modem: Modem) -> bool:
    if not modem.connect():
        return False
    try:
        if "OK" not in modem.send_command(b'AT\r\n'):
            return False
        modem.send_command(b'AT+CMGF=1\r\n')
        modem.send_command(b'AT+CNMI=2,1,0,0,0\r\n')
        modem.send_command(b'AT+CMEE=2\r\n')
        modem.send_command(b'AT^USSDMODE=0\r\n')
        modem.send_command(b'AT+CUSD=1\r\n')
        return True
    finally:
        modem.close()

def delete_all_sms(modem: Modem):
    if not modem.connect():
        return
    try:
        modem.send_command(b'AT+CMGD=1,4\r\n', delay=2.0)
    finally:
        modem.close()

def get_network_operator(modem: Modem) -> Optional[str]:
    if not modem.connect():
        logger.error(f"ไม่สามารถเชื่อมต่อพอร์ต {modem.port} เพื่อตรวจสอบเครือข่าย")
        return None
    try:
        response = modem.send_command(b'AT+COPS?\r\n', delay=1.0)
        logger.debug(f"Network operator response: {response}")
        match = re.search(r'\+COPS: \d+,\d+,"([^"]+)",\d+', response)
        if match:
            operator = match.group(1).lower()
            logger.info(f"พบเครือข่าย: {operator} ที่ {modem.port}")
            return operator
        logger.warning(f"ไม่พบข้อมูลเครือข่ายจาก +COPS ที่ {modem.port}")
        return None
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดในการตรวจสอบเครือข่ายที่ {modem.port}: {e}")
        return None
    finally:
        modem.close()

def check_ussd(modem: Modem, net: str, code: bytes) -> Optional[str]:
    logger.info(f"🔍 เช็คเบอร์ {net} ที่ {modem.port}")
    if not modem.connect():
        logger.error(f"ไม่สามารถเชื่อมต่อพอร์ต {modem.port} สำหรับ USSD")
        return None
    try:
        res = modem.send_command(code, delay=CONFIG["USSD_DELAY"])
        logger.debug(f"USSD raw response from {net} at {modem.port}: {res}")
        match = re.search(r'\+CUSD:\s*\d+,"([^"]+)",?', res)
        if match:
            hex_str = match.group(1)
            logger.debug(f"USSD hex string: {hex_str}")
            decoded = decode_ussd(hex_str)
            phone = extract_phone_number(decoded)
            if phone != "ไม่พบเบอร์":
                logger.info(f"✅ พบเบอร์ {phone} (ตอบจาก USSD {net}) ที่ {modem.port}")
                return phone
            logger.warning(f"ไม่สามารถแยกเบอร์จาก USSD {net}: {decoded}")
        else:
            logger.warning(f"ไม่พบ +CUSD ในการตอบกลับจาก {net} ที่ {modem.port}")
        return None
    finally:
        modem.close()

def get_phone_number(modem: Modem) -> Optional[str]:
    if not modem.connect():
        logger.error(f"ไม่สามารถเชื่อมต่อพอร์ต {modem.port}")
        return None
    try:
        # Check network registration
        if "+CREG: 0,0" in modem.send_command(b'AT+CREG?\r\n'):
            logger.warning(f"โมเด็มที่ {modem.port} ไม่ได้ลงทะเบียนในเครือข่าย")
            return None
        # Define USSD codes for known operators
        ussd_codes = {
            "dtac": b'AT+CUSD=1,"*102#",15\r\n',
            "ais": b'AT+CUSD=1,"*545#",15\r\n',
            "true": b'AT+CUSD=1,"*933#",15\r\n'
        }
        # Get network operator
        modem.close()  # Close connection before getting operator
        operator = get_network_operator(modem)
        if not operator:
            logger.warning(f"ไม่สามารถระบุเครือข่ายได้ที่ {modem.port}")
            send_to_telegram(f"⚠️ {modem.port}: ไม่สามารถระบุเครือข่ายได้")
            return None
        # Normalize operator name for matching
        operator = operator.lower()
        # Map operator names to known keys
        operator_mapping = {
            "dtac": "dtac",
            "happy": "dtac",  # DTAC's alternate branding
            "ais": "ais",
            "true": "true",
            "truemove": "true",
            "truemove h": "true"
        }
        matched_operator = None
        for key, value in operator_mapping.items():
            if key in operator:
                matched_operator = value
                break
        if matched_operator not in ussd_codes:
            logger.warning(f"เครือข่าย {operator} ไม่ได้รับการสนับสนุนที่ {modem.port}")
            send_to_telegram(f"⚠️ {modem.port}: เครือข่าย {operator} ไม่ได้รับการสนับสนุน")
            return None
        # Try USSD for the detected operator
        for attempt in range(2):  # Try twice
            logger.info(f"Attempt {attempt + 1} to get phone number at {modem.port} for {matched_operator}")
            phone = check_ussd(modem, matched_operator, ussd_codes[matched_operator])
            if phone:
                return phone
            logger.info(f"No phone number found in attempt {attempt + 1} at {modem.port}")
        logger.warning(f"❌ ไม่พบเบอร์จาก USSD ที่ {modem.port} หลังจากลอง 2 รอบ")
        return None
    except Exception as e:
        logger.error(f"เกิดข้อผิดพลาดใน get_phone_number ที่ {modem.port}: {e}")
        return None
    finally:
        modem.close()

def read_sms(modem: Modem, stop_event: threading.Event):
    logger.info(f"Start thread for {modem.port}")
    if not modem.connect():
        return
    try:
        while not stop_event.is_set():
            response = modem.send_command(b'', delay=1.0)
            if '+CMTI:' in response:
                match = re.search(r'\+CMTI:\s*"SM",(\d+)', response)
                if match:
                    index = match.group(1)
                    res = modem.send_command(f'AT+CMGR={index}\r\n'.encode(), delay=2.0)
                    sms_lines = res.split('\n')
                    for i, line in enumerate(sms_lines):
                        if '+CMGR:' in line:
                            match = re.match(r'\+CMGR:\s*"[^"]+","([^"]+)",[^,]*,"([^"]+)"', line)
                            if match:
                                sender = match.group(1)
                                timestamp = match.group(2)
                                message = sms_lines[i+1].strip() if i+1 < len(sms_lines) else ""
                                message = decode_sms(message)
                                send_sms_to_telegram(sender, timestamp, message, modem.port, modem.phone_number)
                                modem.send_command(f'AT+CMGD={index}\r\n'.encode())
                    time.sleep(1)
    finally:
        modem.close()
        logger.info(f"Thread for {modem.port} stopped")

def find_huawei_port():
    return [p.device for p in serial.tools.list_ports.comports() if "HUAWEI Mobile Connect - 3G PC UI Interface" in p.description]

def monitor_modems(active_modems, modem_threads):
    while True:
        try:
            current_ports = set(find_huawei_port())
            active_ports = set(active_modems.keys())
            new_ports = current_ports - active_ports
            for port in new_ports:
                if port in modem_threads:
                    logger.debug(f"Port {port} already has an active thread, skipping")
                    continue
                modem = Modem(port)
                if initialize_modem(modem):
                    phone_number = get_phone_number(modem)
                    modem.phone_number = phone_number
                    delete_all_sms(modem)
                    stop_event = threading.Event()
                    thread = threading.Thread(target=read_sms, args=(modem, stop_event))
                    thread.daemon = True
                    modem_threads[port] = (thread, stop_event)
                    active_modems[port] = modem
                    thread.start()
                    send_to_telegram(f"🟢 {port}: {phone_number or 'ไม่ทราบ'}")
            removed_ports = active_ports - current_ports
            for port in removed_ports:
                modem = active_modems.pop(port, None)
                thread, stop_event = modem_threads.pop(port, (None, None))
                if stop_event:
                    stop_event.set()
                    thread.join(timeout=5)
                    if thread.is_alive():
                        logger.warning(f"Thread for {port} ยังไม่จบหลัง timeout")
                    else:
                        logger.info(f"Thread for {port} stopped")
                send_to_telegram(f"🔴 {port} ถอด")
            time.sleep(CONFIG["HOTPLUG_POLL_INTERVAL"])
        except Exception as e:
            logger.error(f"เกิดข้อผิดพลาดใน monitor_modems: {e}")

def main():
    print("🚀 เริ่มระบบ SMS...")
    logger.info("เริ่มต้นระบบ SMS Service...")
    active_modems = {}
    modem_threads = {}
    ports = find_huawei_port()
    if not ports:
        print("❌ ไม่พบโมเด็ม HUAWEI")
        logger.error("ไม่พบ HUAWEI 3G Modem ที่ใช้งานได้")
        return
    modem_info = []
    threads = []
    for port in ports:
        logger.info(f"ตรวจสอบพอร์ต {port}")
        modem = Modem(port)
        active_modems[port] = modem
        logger.debug(f"Added {port} to active_modems")
        thread = threading.Thread(target=lambda m=modem: setattr(m, 'phone_number', get_phone_number(m)))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    for port in ports:
        if port not in active_modems:
            logger.error(f"Port {port} not found in active_modems")
            continue
        modem = active_modems[port]
        if initialize_modem(modem):
            print(f"🟢 พบโมเด็ม: {port} ({modem.phone_number or 'ไม่พบเบอร์'})")
            delete_all_sms(modem)
            modem_info.append((port, modem.phone_number or "ไม่พบเบอร์"))
            if port not in modem_threads:
                stop_event = threading.Event()
                thread = threading.Thread(target=read_sms, args=(modem, stop_event))
                thread.daemon = True
                modem_threads[port] = (thread, stop_event)
                thread.start()
        else:
            print(f"🔴 โมเด็มไม่ตอบสนอง: {port}")
            modem_info.append((port, "ไม่ตอบสนอง"))
    summary = "\n".join([f"📡 ระบบเริ่ม"] + [f"{p}: {n}" for p, n in modem_info])
    send_to_telegram(summary)
    monitor_thread = threading.Thread(target=monitor_modems, args=(active_modems, modem_threads))
    monitor_thread.daemon = True
    monitor_thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 ระบบหยุด")
        logger.info("ระบบถูกหยุดโดยผู้ใช้")
        for port, (thread, stop_event) in list(modem_threads.items()):
            stop_event.set()
            thread.join(timeout=5)
            if thread.is_alive():
                logger.warning(f"Thread for {port} ยังไม่จบหลัง timeout")
            else:
                logger.info(f"Thread for {port} stopped")

if __name__ == "__main__":
    main()
