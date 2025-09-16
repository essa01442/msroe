#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار التكامل الشامل للبوابة الأمنية لمنظومة مسرور
===========================================

هذا السكريبت يختبر التكامل بين جميع مكونات البوابة الأمنية:
- Google Authenticator
- التوقيع الرقمي  
- أدوات الأمان

المؤلف: منظومة مسرور
التاريخ: 2024
"""

import sys
import os
from datetime import datetime

# إضافة المجلد الحالي للمسار
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from google_auth import GoogleAuthenticatorManager
from digital_signature import DigitalSignatureManager  
from security_utils import SecurityUtils

def test_integrated_security_gateway():
    """اختبار التكامل الشامل للبوابة الأمنية"""
    
    print("=" * 60)
    print("اختبار التكامل الشامل للبوابة الأمنية لمنظومة مسرور")
    print("=" * 60)
    
    # تهيئة جميع المكونات
    print("\n1. تهيئة مكونات البوابة الأمنية...")
    auth_manager = GoogleAuthenticatorManager("test_security.db")
    signature_manager = DigitalSignatureManager("test_signatures.db")
    security_utils = SecurityUtils("test_security_utils.db")
    
    # بيانات المستخدم للاختبار
    user_data = {
        'user_id': 'test_user_001',
        'telegram_uid': '987654321',
        'username': 'احمد_محمد_مسرور',
        'password': 'MyStr0ng!P@ssw0rd2024'
    }
    
    print("✓ تم تهيئة جميع المكونات بنجاح")
    
    # الخطوة 2: التحقق من قوة كلمة المرور
    print("\n2. التحقق من قوة كلمة المرور...")
    password_check = security_utils.validate_password_strength(
        user_data['password'], user_data['username']
    )
    
    if password_check['valid']:
        print(f"✓ كلمة المرور قوية ({password_check['strength']}) - النقاط: {password_check['score']}")
    else:
        print(f"✗ كلمة المرور ضعيفة: {password_check['issues']}")
        return False
    
    # الخطوة 3: إنشاء مفتاح التوقيع الرقمي للنظام
    print("\n3. إنشاء مفتاح التوقيع الرقمي للنظام...")
    key_result = signature_manager.generate_keypair(
        "نظام_مسرور_الأمني", "system", expires_days=365
    )
    
    if key_result:
        system_key_id = key_result['key_id']
        system_passphrase = key_result['passphrase']
        print(f"✓ تم إنشاء مفتاح النظام: {system_key_id[:30]}...")
    else:
        print("✗ فشل في إنشاء مفتاح النظام")
        return False
    
    # الخطوة 4: تسجيل المستخدم في Google Authenticator
    print("\n4. تسجيل المستخدم في نظام Google Authenticator...")
    try:
        totp_secret = auth_manager.generate_secret_key(
            user_data['user_id'], 
            user_data['telegram_uid'], 
            user_data['username']
        )
        print(f"✓ تم توليد السر المشترك: {totp_secret[:10]}...")
        
        # إنشاء رمز QR
        qr_path = auth_manager.generate_qr_code(user_data['user_id'], "مسرور")
        if qr_path:
            print(f"✓ تم إنشاء رمز QR: {qr_path}")
        
    except Exception as e:
        print(f"✗ خطأ في تسجيل Google Authenticator: {e}")
        return False
    
    # الخطوة 5: توقيع بيانات التسجيل رقمياً
    print("\n5. توقيع بيانات التسجيل رقمياً...")
    registration_data = {
        'user_id': user_data['user_id'],
        'username': user_data['username'],
        'telegram_uid': user_data['telegram_uid'],
        'registration_time': datetime.now().isoformat(),
        'totp_configured': True
    }
    
    signature_id = signature_manager.sign_message(
        system_key_id,
        str(registration_data),
        "user_registration",
        registration_data,
        system_passphrase
    )
    
    if signature_id:
        print(f"✓ تم توقيع بيانات التسجيل: {signature_id[:30]}...")
    else:
        print("✗ فشل في توقيع بيانات التسجيل")
        return False
    
    # الخطوة 6: محاكاة عملية مصادقة ناجحة
    print("\n6. اختبار عملية المصادقة...")
    
    # توليد رمز TOTP حالي
    import pyotp
    totp = pyotp.TOTP(totp_secret)
    current_totp = totp.now()
    
    # التحقق من الرمز
    auth_result = auth_manager.verify_totp_code(
        user_data['user_id'],
        current_totp,
        user_data['telegram_uid'],
        "192.168.1.100",
        "Mozilla/5.0 (Test Browser)"
    )
    
    if auth_result['success']:
        print("✓ نجحت عملية المصادقة")
        
        # توقيع حدث الدخول الناجح
        login_event = {
            'user_id': user_data['user_id'],
            'login_time': datetime.now().isoformat(),
            'ip_address': "192.168.1.100",
            'method': 'totp',
            'success': True
        }
        
        login_signature = signature_manager.sign_message(
            system_key_id,
            str(login_event),
            "successful_login",
            login_event,
            system_passphrase
        )
        
        print(f"✓ تم توقيع حدث الدخول: {login_signature[:30]}...")
        
    else:
        print(f"✗ فشلت المصادقة: {auth_result['message']}")
        return False
    
    # الخطوة 7: اختبار آليات الحماية
    print("\n7. اختبار آليات الحماية...")
    
    # محاكاة محاولة فاشلة
    failed_attempt = security_utils.record_failed_attempt(
        "attacker_001",
        "user",
        "login", 
        "192.168.1.200",
        "BadBot/1.0",
        "محاولة دخول بكلمة مرور خاطئة",
        3
    )
    
    print(f"✓ تم تسجيل محاولة فاشلة - العدد: {failed_attempt.get('attempt_count', 0)}")
    
    # اختبار حدود المعدل
    rate_limit = security_utils.check_rate_limit("192.168.1.200", "ip")
    if rate_limit['allowed']:
        print(f"✓ حدود المعدل: {rate_limit['current_count']}/{rate_limit['max_requests']}")
    
    # الخطوة 8: التحقق من التوقيعات
    print("\n8. التحقق من صحة التوقيعات...")
    
    # التحقق من توقيع التسجيل
    reg_verification = signature_manager.verify_signature(
        signature_id,
        str(registration_data),
        "نظام_التحقق"
    )
    
    if reg_verification['valid']:
        print("✓ توقيع التسجيل صحيح ومعتمد")
    else:
        print(f"✗ توقيع التسجيل غير صحيح: {reg_verification['message']}")
        return False
    
    # التحقق من توقيع الدخول
    login_verification = signature_manager.verify_signature(
        login_signature,
        str(login_event),
        "نظام_التحقق"
    )
    
    if login_verification['valid']:
        print("✓ توقيع الدخول صحيح ومعتمد")
    else:
        print(f"✗ توقيع الدخول غير صحيح: {login_verification['message']}")
        return False
    
    # الخطوة 9: إنشاء التقارير
    print("\n9. إنشاء التقارير الأمنية...")
    
    # تقرير المصادقة
    auth_stats = auth_manager.get_auth_statistics(user_data['user_id'], 1)
    print(f"✓ إحصائيات المصادقة: {auth_stats['successful_attempts']} ناجحة من {auth_stats['total_attempts']}")
    
    # تقرير التوقيعات
    sig_stats = signature_manager.get_signature_statistics(system_key_id, 1)
    print(f"✓ إحصائيات التوقيعات: {sig_stats['total_signatures']} توقيع، {sig_stats['total_verifications']} تحقق")
    
    # تقرير الأمان العام
    security_report = security_utils.get_security_report(1)
    print(f"✓ التقرير الأمني: {security_report['failed_attempts']['total']} محاولة فاشلة")
    
    print("\n" + "=" * 60)
    print("✅ تم اختبار التكامل الشامل بنجاح!")
    print("جميع مكونات البوابة الأمنية تعمل بشكل صحيح ومتكامل")
    print("=" * 60)
    
    return True

def cleanup_test_files():
    """تنظيف ملفات الاختبار"""
    import os
    test_files = [
        "test_security.db",
        "test_signatures.db", 
        "test_security_utils.db"
    ]
    
    for file in test_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"تم حذف ملف الاختبار: {file}")

if __name__ == "__main__":
    try:
        success = test_integrated_security_gateway()
        
        if success:
            print("\n🎉 نجح اختبار التكامل الشامل!")
            print("البوابة الأمنية جاهزة للاستخدام في منظومة مسرور")
        else:
            print("\n❌ فشل في بعض اختبارات التكامل")
            print("يرجى مراجعة الأخطاء أعلاه")
    
    except Exception as e:
        print(f"\n💥 خطأ غير متوقع أثناء الاختبار: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # تنظيف ملفات الاختبار
        print("\nتنظيف ملفات الاختبار...")
        cleanup_test_files()
        print("انتهى الاختبار.")