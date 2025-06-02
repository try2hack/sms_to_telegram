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
logger.setLevel(logging.INFO)
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
    "USSD_DELAY": 5
}

port_lock = threading.Lock()

# Utility Functions
def decode_ucs2(hex_str: str) -> str:
    if not re.fullmatch(r'[0-9A-Fa-f]+', hex_str) or len(hex_str) % 4 != 0:
        return hex_str
    try:
        return bytes.fromhex(hex_str).decode('utf-16-be')
    except Exception as e:
        logger.error(f"Error decoding UCS2: {e}")
        return hex_str

def extract_phone_number(decoded: str) -> str:
    match = re.search(r'(\+66\d{8,9}|\d{10})', decoded)
    return match.group(0) if match else "ไม่พบเบอร์"

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

# Modem Class
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
                return True
            except serial.SerialException as e:
                if "PermissionError(13" in str(e):
                    return False  # ข้ามการ log สำหรับ PermissionError(13)
                logger.error(f"เชื่อมต่อพอร์ต {self.port} ไม่สำเร็จ: {e}")
                return False

    def close(self):
        if self.serial and self.serial.is_open:
            try:
                self.serial.close()
            except Exception as e:
                logger.error(f"ปิดพอร์ต {self.port} ล้มเหลว: {e}")

    def send_command(self, command: bytes, delay: float = 1.0) -> str:
        try:
            self.serial.write(command)
            time.sleep(delay)
            return self.serial.read(self.serial.in_waiting).decode('ascii', errors='ignore')
        except serial.SerialException as e:
            if "PermissionError(13" in str(e):
                return ""  # ข้ามการ log สำหรับ PermissionError(13)
            logger.error(f"ส่งคำสั่งที่ {self.port} ล้มเหลว: {e}")
            return ""

# Modem Logic
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

def get_phone_number(modem: Modem) -> Optional[str]:
    if not modem.connect():
        return None
    try:
        if "+CREG: 0,0" in modem.send_command(b'AT+CREG?\r\n'):
            return None
        ussd_codes = [
            ("DTAC", b'AT+CUSD=1,"*102#",15\r\n'),
            ("AIS", b'AT+CUSD=1,"*545#",15\r\n'),
            ("True", b'AT+CUSD=1,"*933#",15\r\n')
        ]
        # ลองรอบแรก
        for net, code in ussd_codes:
            logger.info(f"🔍 รอบที่ 1: เช็คเบอร์ {net} ที่ {modem.port}")
            res = modem.send_command(code, delay=CONFIG["USSD_DELAY"])
            match = re.search(r'\+CUSD:\s*\d+,"([^"]+)"', res)
            if match:
                decoded = decode_ucs2(match.group(1))
                phone = extract_phone_number(decoded)
                if phone != "ไม่พบเบอร์":
                    logger.info(f"✅ พบเบอร์ {phone} จาก {net} ที่ {modem.port}")
                    return phone
        # ถ้ารอบแรกไม่พบ ลองรอบที่สอง
        logger.info(f"🔄 รอบที่ 2: วนเช็คเบอร์ใหม่ที่ {modem.port}")
        for net, code in ussd_codes:
            logger.info(f"🔍 รอบที่ 2: เช็คเบอร์ {net} ที่ {modem.port}")
            res = modem.send_command(code, delay=CONFIG["USSD_DELAY"])
            match = re.search(r'\+CUSD:\s*\d+,"([^"]+)"', res)
            if match:
                decoded = decode_ucs2(match.group(1))
                phone = extract_phone_number(decoded)
                if phone != "ไม่พบเบอร์":
                    logger.info(f"✅ พบเบอร์ {phone} จาก {net} ที่ {modem.port}")
                    return phone
        logger.warning(f"❌ ไม่พบเบอร์จาก USSD ที่ {modem.port}")
        return None
    finally:
        modem.close()

def read_sms(modem: Modem, stop_event: threading.Event):
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
                                message = decode_ucs2(message)
                                send_sms_to_telegram(sender, timestamp, message, modem.port, modem.phone_number)
                                modem.send_command(f'AT+CMGD={index}\r\n'.encode())
            time.sleep(1)
    finally:
        modem.close()

def find_huawei_port():
    return [p.device for p in serial.tools.list_ports.comports() if "HUAWEI Mobile Connect - 3G PC UI Interface" in p.description]

def monitor_modems(active_modems, modem_threads):
    while True:
        try:
            current_ports = set(find_huawei_port())
            active_ports = set(active_modems.keys())
            new_ports = current_ports - active_ports
            for port in new_ports:
                modem = Modem(port)
                if initialize_modem(modem):
                    phone_number = get_phone_number(modem)
                    modem.phone_number = phone_number
                    active_modems[port] = modem
                    delete_all_sms(modem)
                    stop_event = threading.Event()
                    thread = threading.Thread(target=read_sms, args=(modem, stop_event))
                    thread.daemon = True
                    modem_threads[port] = (thread, stop_event)
                    thread.start()
                    send_to_telegram(f"🟢 {port}: {phone_number or 'ไม่ทราบ'}")

            removed_ports = active_ports - current_ports
            for port in removed_ports:
                modem = active_modems.pop(port)
                thread, stop_event = modem_threads.pop(port)
                stop_event.set()
                thread.join()
                send_to_telegram(f"🔴 {port} ถอด")

            time.sleep(CONFIG["HOTPLUG_POLL_INTERVAL"])
        except Exception as e:
            logger.error(f"เกิดข้อผิดพลาดใน monitor_modems: {e}")

# Main
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
        thread = threading.Thread(target=lambda m=modem: setattr(m, 'phone_number', get_phone_number(m)))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        active_modems[port] = modem

    for thread in threads:
        thread.join()

    for port in ports:
        modem = active_modems[port]
        if initialize_modem(modem):
            print(f"🟢 พบโมเด็ม: {port} ({modem.phone_number or 'ไม่พบเบอร์'})")
            delete_all_sms(modem)
            modem_info.append((port, modem.phone_number or "ไม่พบเบอร์"))
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
        for _, (thread, stop_event) in modem_threads.items():
            stop_event.set()
            thread.join()

if __name__ == "__main__":
    main()
