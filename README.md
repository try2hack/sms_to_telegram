SMS Hotplug 🔥
สคริปต์ Python สุดเท่ (smsV5_1_hotplug.py) สำหรับจัดการ SMS ผ่านโมเด็ม HUAWEI 3G แบบ Hotplug! ตรวจจับโมเด็มอัตโนมัติ อ่าน SMS ส่งต่อไป Telegram และรองรับเครือข่าย DTAC, AIS, True เพื่อดึงเบอร์โทร
ฟีเจอร์เด็ด

Hotplug สุดล้ำ: ต่อ/ถอดโมเด็มได้แบบไม่สะดุด
SMS จัดเต็ม: อ่านและถอดรหัส SMS ส่งตรงถึง Telegram
หาเบอร์ไว: ดึงเบอร์โทรผ่าน USSD รองรับเครือข่ายดัง
Log เท่ๆ: บันทึกทุกอย่างลง sms_service.log และคอนโซล
มัลติเธรด: จัดการหลายโมเด็มพร้อมกันแบบเนียนๆ

เริ่มใช้งาน

ติดตั้ง Python 3.6+ และแพ็กเกจ:pip install pyserial requests


เสียบโมเด็ม HUAWEI 3G
แก้ TELEGRAM_BOT_TOKEN และ TELEGRAM_CHAT_ID ในสคริปต์
รันเลย:python smsV5_1_hotplug.py


กด Ctrl+C เพื่อหยุด

การตั้งค่า
ปรับแต่งได้ใน CONFIG:

SERIAL_BAUDRATE: 115200
SERIAL_TIMEOUT: 10 วินาที
HOTPLUG_POLL_INTERVAL: 10 วินาที
USSD_DELAY: 5 วินาที

ไฟล์

smsV5_1_hotplug.py: สคริปต์หลัก
sms_service.log: ไฟล์บันทึก
README.md: ไฟล์นี้!

หมายเหตุ

ใช้โมเด็ม HUAWEI ที่มี "3G PC UI Interface"
รหัส USSD: DTAC (*102#), AIS (*545#), True (*933#)
ต้องมีสิทธิ์เข้าถึงพอร์ต serial

สัญญาอนุญาต
MIT License – ใช้ได้ตามสบาย!
อยากแจม?
ยินดีต้อนรับ! ส่ง pull request หรือเปิด issue บน GitHub ได้เลย
