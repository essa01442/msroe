# دليل بناء وكيل المصادقة (Google Authenticator)

هذا الدليل يشرح خطوة بخطوة كيفية بناء وتفعيل وكيل المصادقة متعددة العوامل (MFA/2FA) باستخدام نظام TOTP، بالاعتماد على كود `google_auth.py`.

---

### **الهدف من الوكيل**

توفير طبقة أمان إضافية عند تسجيل الدخول عبر طلب رمز متغير يتم توليده من تطبيق Google Authenticator على هاتف المستخدم.

---

### **المتطلبات الأساسية**

تأكد من تثبيت المكتبات التالية:

```bash
pip install pyotp qrcode[pil] cryptography
```

---

### **خطوات البناء والتنفيذ**

#### **الخطوة 1: تهيئة مدير المصادقة**

أول خطوة هي إنشاء كائن من الكلاس `GoogleAuthenticatorManager`. هذا الكائن سيدير جميع العمليات المتعلقة بالمصادقة.

```python
from google_auth import GoogleAuthenticatorManager

# سيقوم الكائن بإنشاء قاعدة بيانات "مسرور_security.db" تلقائياً
auth_manager = GoogleAuthenticatorManager(db_path="مسرور_security.db")
```

#### **الخطوة 2: تسجيل مستخدم جديد وتوليد السر المشترك**

عند تسجيل مستخدم جديد في نظامك، يجب توليد "سر مشترك" فريد له. هذا السر هو أساس عملية المصادقة.

```python
# بيانات المستخدم
user_id = "user001"
telegram_uid = "123456789"  # معرف فريد آخر للمستخدم
username = "احمد_محمد"

# توليد السر وتخزينه بشكل مشفر في قاعدة البيانات
secret_key = auth_manager.generate_secret_key(user_id, telegram_uid, username)

print(f"السر المشترك للمستخدم {username} هو: {secret_key}")
```
**ماذا يحدث في الخلفية؟**
1.  يتم توليد سر عشوائي بصيغة `base32`.
2.  يتم تشفير هذا السر وتخزينه في جدول `user_secrets` في قاعدة البيانات.
3.  يتم إنشاء 8 رموز احتياطية مشفرة لنفس المستخدم.

#### **الخطوة 3: إنشاء رمز الاستجابة السريعة (QR Code)**

لكي يتمكن المستخدم من إضافة حسابه إلى تطبيق Google Authenticator، يجب عرض رمز QR له ليقوم بمسحه.

```python
# إنشاء رمز QR للمستخدم وتخزينه كصورة
qr_code_path = auth_manager.generate_qr_code(user_id, service_name="منظومة مسرور")

if qr_code_path:
    print(f"تم إنشاء رمز QR. اعرض الصورة الموجودة في المسار التالي للمستخدم: {qr_code_path}")
else:
    print("فشل إنشاء رمز QR.")
```
**ملاحظة**: يجب عرض هذه الصورة للمستخدم لمرة واحدة فقط أثناء عملية الإعداد.

#### **الخطوة 4: التحقق من الرمز المؤقت (عملية الدخول)**

عندما يحاول المستخدم تسجيل الدخول، سيُطلب منه إدخال الرمز المكون من 6 أرقام من تطبيق Google Authenticator.

```python
# الرمز الذي أدخله المستخدم من التطبيق
user_entered_code = "123456" 
ip_address = "192.168.1.10" # IP الخاص بالمستخدم (مهم للأمان)

# التحقق من صحة الرمز
verification_result = auth_manager.verify_totp_code(
    user_id=user_id,
    code=user_entered_code,
    ip_address=ip_address
)

if verification_result['success']:
    print("تم التحقق بنجاح. يمكن للمستخدم الدخول.")
else:
    print(f"فشل التحقق: {verification_result['message']}")
    # إذا فشلت المحاولات، سيتم قفل الحساب مؤقتاً
    if verification_result['user_locked']:
        print(f"الحساب مقفل حتى: {verification_result['lockout_time']}")
```

#### **الخطوة 5: التعامل مع الرموز الاحتياطية**

إذا فقد المستخدم هاتفه، يمكنه استخدام أحد الرموز الاحتياطية التي تم إنشاؤها في الخطوة 2.

```python
# أولاً، عرض الرموز للمستخدم (يجب أن يفعل ذلك في مكان آمن)
backup_codes = auth_manager.get_backup_codes(user_id)
print(f"الرموز الاحتياطية: {backup_codes}")

# ثانياً، التحقق من الرمز الاحتياطي عند الحاجة
is_backup_valid = auth_manager.verify_backup_code(user_id, "87654321")
if is_backup_valid:
    print("تم التحقق باستخدام الرمز الاحتياطي.")
    # ملاحظة: يتم حذف الرمز بعد استخدامه
```

---
### **هيكل قاعدة البيانات (`مسرور_security.db`)**

*   **`user_secrets`**: يخزن المعلومات الأساسية للمستخدمين، السر المشفر، الرموز الاحتياطية، وحالة الحساب.
*   **`auth_attempts`**: سجل لجميع محاولات المصادقة (الناجحة والفاشلة)، ويستخدم للمراقبة والتحليل الأمني.

بهذه الخطوات، تكون قد قمت ببناء وتفعيل نظام مصادقة ثنائية قوي وآمن.
