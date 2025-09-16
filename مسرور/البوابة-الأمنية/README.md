# البوابة الأمنية لمنظومة مسرور - دليل الإعداد والاستخدام

## نظرة عامة

تتكون البوابة الأمنية من ثلاثة مكونات رئيسية لحماية منظومة مسرور:

1. **Google Authenticator** - نظام المصادقة متعددة العوامل
2. **التوقيع الرقمي** - ضمان سلامة الرسائل والبيانات
3. **أدوات الأمان** - حماية من الهجمات وإدارة المحاولات الفاشلة

## متطلبات النظام

### المكتبات المطلوبة

```bash
pip install -r requirements.txt
```

المكتبات الأساسية:
- `pyotp==2.9.0` - للتعامل مع TOTP
- `qrcode[pil]==7.4.2` - لإنشاء رموز QR  
- `cryptography==41.0.7` - للتشفير والتوقيع الرقمي
- `bcrypt==4.1.2` - لتشفير كلمات المرور
- `pillow==10.1.0` - لمعالجة الصور

### قواعد البيانات

النظام يستخدم SQLite لتخزين البيانات الأمنية:
- `مسرور_security.db` - بيانات Google Authenticator
- `مسرور_signatures.db` - بيانات التوقيع الرقمي
- `مسرور_security_utils.db` - بيانات الأمان العامة

## 1. نظام Google Authenticator

### الإعداد الأولي

```python
from google_auth import GoogleAuthenticatorManager

# إنشاء مدير المصادقة
auth_manager = GoogleAuthenticatorManager()

# توليد سر مشترك للمستخدم
user_id = "user001"
telegram_uid = "123456789"
username = "احمد_محمد"

secret = auth_manager.generate_secret_key(user_id, telegram_uid, username)
print(f"السر المشترك: {secret}")
```

### إنشاء رمز QR

```python
# إنشاء رمز QR للمستخدم
qr_path = auth_manager.generate_qr_code(user_id, "مسرور")
print(f"رمز QR محفوظ في: {qr_path}")
```

### التحقق من الرمز

```python
# التحقق من رمز TOTP
verification_result = auth_manager.verify_totp_code(
    user_id=user_id,
    code="123456",  # الرمز من التطبيق
    telegram_uid=telegram_uid,
    ip_address="192.168.1.100"
)

if verification_result['success']:
    print("تم التحقق بنجاح")
else:
    print(f"فشل التحقق: {verification_result['message']}")
```

### رموز النسخ الاحتياطية

```python
# الحصول على رموز النسخ الاحتياطية
backup_codes = auth_manager.get_backup_codes(user_id)
print(f"رموز النسخ الاحتياطية: {backup_codes}")

# استخدام رمز نسخ احتياطي
backup_success = auth_manager.verify_backup_code(user_id, "12345678")
```

## 2. نظام التوقيع الرقمي

### توليد مفاتيح التوقيع

```python
from digital_signature import DigitalSignatureManager

# إنشاء مدير التوقيع الرقمي
signature_manager = DigitalSignatureManager()

# توليد زوج مفاتيح
key_id = signature_manager.generate_keypair(
    entity_name="نظام_مسرور",
    entity_type="system",
    expires_days=365
)
print(f"معرف المفتاح: {key_id}")
```

### توقيع الرسائل

```python
# توقيع رسالة
message = "معاملة مالية: تحويل 1000 ريال من حساب A إلى حساب B"
signature_id = signature_manager.sign_message(
    key_id=key_id,
    message=message,
    message_type="financial_transaction",
    metadata={"amount": 1000, "from": "A", "to": "B"}
)
print(f"معرف التوقيع: {signature_id}")
```

### التحقق من التوقيع

```python
# التحقق من صحة التوقيع
verification_result = signature_manager.verify_signature(
    signature_id=signature_id,
    message=message,
    verifier_info="نظام_التدقيق"
)

if verification_result['valid']:
    print("التوقيع صحيح ومعتمد")
else:
    print(f"التوقيع غير صحيح: {verification_result['message']}")
```

### إنشاء رسائل مع طوابع زمنية

```python
# إنشاء رسالة مع طابع زمني
timestamped_message = signature_manager.create_timestamped_message(
    message={"action": "login", "user": "احمد"},
    message_type="auth_log"
)
print(f"الرسالة مع الطابع الزمني: {timestamped_message}")
```

## 3. أدوات الأمان

### إدارة المحاولات الفاشلة

```python
from security_utils import SecurityUtils

# إنشاء مدير الأمان
security_utils = SecurityUtils()

# تسجيل محاولة فاشلة
attempt_result = security_utils.record_failed_attempt(
    identifier="user001",
    identifier_type="user",
    attempt_type="login",
    ip_address="192.168.1.100",
    details="كلمة مرور خاطئة",
    severity=2
)

print(f"عدد المحاولات: {attempt_result['attempt_count']}")
print(f"هل تم الحظر: {attempt_result['blocked']}")
```

### التحقق من حالة الحظر

```python
# التحقق من حالة الحظر
block_status = security_utils.check_block_status("user001", "user")

if block_status['blocked']:
    print(f"الحساب محظور حتى: {block_status['blocked_until']}")
    print(f"السبب: {block_status['reason']}")
    print(f"الوقت المتبقي: {block_status['remaining_minutes']} دقيقة")
else:
    print("الحساب غير محظور")
```

### حدود المعدل (Rate Limiting)

```python
# التحقق من حدود المعدل
rate_limit = security_utils.check_rate_limit("192.168.1.100", "ip")

if rate_limit['allowed']:
    print("الطلب مسموح")
    print(f"العدد الحالي: {rate_limit['current_count']}/{rate_limit['max_requests']}")
else:
    print("تم تجاوز حد المعدل")
    print(f"إعادة التعيين في: {rate_limit['reset_time']}")
```

### التحقق من قوة كلمة المرور

```python
# فحص قوة كلمة المرور
password_check = security_utils.validate_password_strength(
    password="MyStr0ng!P@ssw0rd",
    username="ahmed123"
)

print(f"كلمة المرور صالحة: {password_check['valid']}")
print(f"القوة: {password_check['strength']}")
print(f"النقاط: {password_check['score']}")

if password_check['issues']:
    print("المشاكل:", password_check['issues'])
if password_check['suggestions']:
    print("الاقتراحات:", password_check['suggestions'])
```

### تشفير كلمات المرور

```python
# تشفير كلمة المرور
password = "كلمة_المرور_الآمنة123!"
hashed_password = security_utils.hash_password(password)

# التحقق من كلمة المرور
is_correct = security_utils.verify_password(password, hashed_password)
print(f"كلمة المرور صحيحة: {is_correct}")
```

### حماية المدخلات

```python
# التحقق من صحة المدخلات
input_validation = security_utils.validate_input(
    input_data="اسم_المستخدم_123",
    input_type="username"
)

if input_validation['valid']:
    print(f"البيانات آمنة: {input_validation['cleaned_data']}")
else:
    print(f"البيانات خطيرة: {input_validation['warnings']}")
```

## نموذج تطبيق متكامل

```python
#!/usr/bin/env python3
from google_auth import GoogleAuthenticatorManager
from digital_signature import DigitalSignatureManager
from security_utils import SecurityUtils

class SecureLoginSystem:
    def __init__(self):
        self.auth_manager = GoogleAuthenticatorManager()
        self.signature_manager = DigitalSignatureManager()
        self.security_utils = SecurityUtils()
        
        # توليد مفتاح النظام
        self.system_key = self.signature_manager.generate_keypair(
            "نظام_الدخول_الآمن", "system"
        )
    
    def register_user(self, user_id: str, telegram_uid: str, 
                     username: str, password: str) -> dict:
        """تسجيل مستخدم جديد"""
        
        # التحقق من قوة كلمة المرور
        password_check = self.security_utils.validate_password_strength(
            password, username
        )
        
        if not password_check['valid']:
            return {
                'success': False,
                'message': 'كلمة المرور ضعيفة',
                'issues': password_check['issues']
            }
        
        # تشفير كلمة المرور
        hashed_password = self.security_utils.hash_password(password)
        
        # توليد سر Google Authenticator
        totp_secret = self.auth_manager.generate_secret_key(
            user_id, telegram_uid, username
        )
        
        # إنشاء رمز QR
        qr_path = self.auth_manager.generate_qr_code(user_id)
        
        # توقيع بيانات التسجيل
        registration_data = {
            'user_id': user_id,
            'username': username,
            'telegram_uid': telegram_uid,
            'registration_time': datetime.now().isoformat()
        }
        
        signature_id = self.signature_manager.sign_message(
            self.system_key,
            str(registration_data),
            "user_registration",
            registration_data
        )
        
        return {
            'success': True,
            'message': 'تم التسجيل بنجاح',
            'qr_code_path': qr_path,
            'signature_id': signature_id
        }
    
    def authenticate_user(self, user_id: str, password: str, 
                         totp_code: str, telegram_uid: str,
                         ip_address: str = None) -> dict:
        """مصادقة المستخدم"""
        
        # التحقق من حالة الحظر
        block_status = self.security_utils.check_block_status(user_id, "user")
        if block_status['blocked']:
            return {
                'success': False,
                'message': f"الحساب محظور حتى {block_status['blocked_until']}",
                'blocked': True
            }
        
        # التحقق من حدود المعدل
        rate_limit = self.security_utils.check_rate_limit(
            ip_address or "unknown", "ip"
        )
        if not rate_limit['allowed']:
            return {
                'success': False,
                'message': 'تم تجاوز حد الطلبات المسموح',
                'rate_limited': True
            }
        
        # TODO: التحقق من كلمة المرور (يحتاج قاعدة بيانات المستخدمين)
        
        # التحقق من رمز TOTP
        totp_result = self.auth_manager.verify_totp_code(
            user_id, totp_code, telegram_uid, ip_address
        )
        
        if not totp_result['success']:
            # تسجيل محاولة فاشلة
            self.security_utils.record_failed_attempt(
                user_id, "user", "totp_verification",
                ip_address, details=totp_result['message']
            )
            return {
                'success': False,
                'message': totp_result['message'],
                'remaining_attempts': totp_result['remaining_attempts']
            }
        
        # توقيع حدث الدخول الناجح
        login_data = {
            'user_id': user_id,
            'login_time': datetime.now().isoformat(),
            'ip_address': ip_address,
            'method': 'totp'
        }
        
        signature_id = self.signature_manager.sign_message(
            self.system_key,
            str(login_data),
            "successful_login",
            login_data
        )
        
        return {
            'success': True,
            'message': 'تم الدخول بنجاح',
            'signature_id': signature_id
        }

# مثال للاستخدام
if __name__ == "__main__":
    from datetime import datetime
    
    login_system = SecureLoginSystem()
    
    # تسجيل مستخدم جديد
    registration = login_system.register_user(
        "ahmed001", "123456789", "احمد_محمد", "MyStr0ng!P@ssw0rd"
    )
    print("نتيجة التسجيل:", registration)
    
    # محاولة الدخول
    if registration['success']:
        # محاكاة إدخال رمز TOTP (في التطبيق الحقيقي سيأتي من المستخدم)
        import pyotp
        secret = login_system.auth_manager._get_user_secret("ahmed001")
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        authentication = login_system.authenticate_user(
            "ahmed001", "MyStr0ng!P@ssw0rd", current_code, 
            "123456789", "192.168.1.100"
        )
        print("نتيجة المصادقة:", authentication)
```

## التقارير والمراقبة

### الحصول على إحصائيات Google Authenticator

```python
# إحصائيات المصادقة
auth_stats = auth_manager.get_auth_statistics("user001", days=30)
print("إحصائيات المصادقة:", auth_stats)
```

### الحصول على إحصائيات التوقيع الرقمي

```python
# إحصائيات التوقيعات
signature_stats = signature_manager.get_signature_statistics(key_id, days=30)
print("إحصائيات التوقيعات:", signature_stats)
```

### التقرير الأمني الشامل

```python
# التقرير الأمني
security_report = security_utils.get_security_report(days=7)
print("التقرير الأمني:", security_report)
```

### تنظيف البيانات القديمة

```python
# تنظيف السجلات القديمة
cleanup_result = security_utils.cleanup_old_records(days_to_keep=90)
print("نتيجة التنظيف:", cleanup_result)
```

## الصيانة والتحديث

### النسخ الاحتياطية

يُنصح بعمل نسخ احتياطية دورية لقواعد البيانات:

```bash
# نسخ احتياطي يومي
cp مسرور_security.db backup/security_$(date +%Y%m%d).db
cp مسرور_signatures.db backup/signatures_$(date +%Y%m%d).db
cp مسرور_security_utils.db backup/utils_$(date +%Y%m%d).db
```

### مراقبة الأداء

- مراقبة حجم قواعد البيانات
- مراقبة عدد المحاولات الفاشلة
- مراقبة استخدام الذاكرة والمعالج
- مراقبة سرعة الاستجابة

### التحديثات الأمنية

- تحديث المكتبات بانتظام
- مراجعة سجلات الأمان
- تحديث كلمات المرور والمفاتيح
- مراجعة إعدادات الحظر والحدود

## استكشاف الأخطاء

### مشاكل شائعة وحلولها

1. **خطأ في إنشاء قاعدة البيانات**
   ```python
   # التأكد من الصلاحيات
   import os
   os.chmod(".", 0o755)
   ```

2. **فشل في التحقق من TOTP**
   - التأكد من صحة الوقت على الخادم
   - التحقق من السر المشترك
   - فحص النافذة الزمنية المسموحة

3. **مشاكل التوقيع الرقمي**
   - التحقق من صحة المفاتيح
   - فحص تاريخ انتهاء الصلاحية
   - التأكد من كلمة مرور المفتاح الخاص

## الأمان والإشادات الهامة

⚠️ **تحذيرات أمنية:**

1. **حماية قواعد البيانات**: تأكد من تشفير قواعد البيانات وحمايتها بكلمات مرور قوية
2. **نقل المفاتيح**: لا تنقل المفاتيح الخاصة عبر قنوات غير مشفرة
3. **النسخ الاحتياطية**: شفر النسخ الاحتياطية وخزنها في مكان آمن
4. **السجلات**: راجع سجلات الأمان بانتظام للكشف عن الأنشطة المشبوهة
5. **التحديثات**: حدث النظام والمكتبات بانتظام لإصلاح الثغرات الأمنية

## الدعم والصيانة

للحصول على الدعم أو الإبلاغ عن مشاكل:
- راجع سجلات النظام في مجلد `logs/`
- تحقق من التقارير الأمنية الدورية
- تواصل مع فريق الأمان السيبراني

---

**© 2024 منظومة مسرور - البوابة الأمنية**