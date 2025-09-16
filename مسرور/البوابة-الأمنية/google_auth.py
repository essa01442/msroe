#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
البوابة الأمنية لمنظومة مسرور - تكامل Google Authenticator
===================================================

هذا الملف يحتوي على وظائف إدارة Google Authenticator للمصادقة متعددة العوامل
في بوابة الأمان لمنظومة مسرور.

المتطلبات:
- pyotp: للتعامل مع TOTP
- qrcode: لإنشاء رموز QR
- cryptography: للتشفير والأمان

المؤلف: منظومة مسرور
التاريخ: 2024
"""

import pyotp
import qrcode
import qrcode.image.svg
import sqlite3
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json


class GoogleAuthenticatorManager:
    """
    مدير Google Authenticator للمصادقة متعددة العوامل
    
    يوفر وظائف:
    - توليد السر المشترك
    - إنشاء رموز QR
    - التحقق من الرمز المؤقت
    - تخزين واسترجاع البيانات الآمنة
    """
    
    def __init__(self, db_path: str = "مسرور_security.db", encryption_key: Optional[bytes] = None):
        """
        تهيئة مدير Google Authenticator
        
        Args:
            db_path: مسار قاعدة البيانات
            encryption_key: مفتاح التشفير (سيتم توليده تلقائياً إن لم يُقدم)
        """
        self.db_path = db_path
        self.encryption_key = encryption_key or self._generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self._init_database()
    
    def _generate_encryption_key(self) -> bytes:
        """
        توليد مفتاح تشفير آمن
        
        Returns:
            مفتاح التشفير المولد
        """
        # استخدام PBKDF2 لتوليد مفتاح آمن
        password = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _init_database(self):
        """تهيئة قاعدة البيانات وإنشاء الجداول المطلوبة"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_secrets (
                    user_id TEXT PRIMARY KEY,
                    telegram_uid TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_secret TEXT NOT NULL,
                    backup_codes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    telegram_uid TEXT NOT NULL,
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    error_message TEXT
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_user_attempts 
                ON auth_attempts(user_id, attempt_time)
            ''')
            
            conn.commit()
    
    def generate_secret_key(self, user_id: str, telegram_uid: str, username: str) -> str:
        """
        توليد سر مشترك فريد للمستخدم
        
        Args:
            user_id: معرف المستخدم الفريد
            telegram_uid: معرف Telegram للمستخدم
            username: اسم المستخدم
            
        Returns:
            السر المشترك المولد (base32)
        """
        # توليد سر عشوائي آمن
        secret = pyotp.random_base32()
        
        # تشفير السر قبل التخزين
        encrypted_secret = self.cipher_suite.encrypt(secret.encode())
        
        # توليد رموز النسخ الاحتياطية
        backup_codes = self._generate_backup_codes()
        encrypted_backup_codes = self.cipher_suite.encrypt(
            json.dumps(backup_codes).encode()
        )
        
        # حفظ في قاعدة البيانات
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO user_secrets 
                (user_id, telegram_uid, username, encrypted_secret, backup_codes, failed_attempts)
                VALUES (?, ?, ?, ?, ?, 0)
            ''', (user_id, telegram_uid, username, 
                  encrypted_secret.decode(), encrypted_backup_codes.decode()))
            conn.commit()
        
        return secret
    
    def _generate_backup_codes(self, count: int = 8) -> list:
        """
        توليد رموز النسخ الاحتياطية
        
        Args:
            count: عدد الرموز المطلوب توليدها
            
        Returns:
            قائمة برموز النسخ الاحتياطية
        """
        backup_codes = []
        for _ in range(count):
            # توليد رمز من 8 أرقام
            code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            backup_codes.append(code)
        return backup_codes
    
    def generate_qr_code(self, user_id: str, service_name: str = "مسرور") -> Optional[str]:
        """
        إنشاء رمز QR للمستخدم
        
        Args:
            user_id: معرف المستخدم
            service_name: اسم الخدمة
            
        Returns:
            مسار ملف QR أو None في حالة الخطأ
        """
        try:
            # استرجاع السر المشترك
            secret = self._get_user_secret(user_id)
            if not secret:
                return None
            
            # إنشاء TOTP URI
            totp = pyotp.TOTP(secret)
            
            # الحصول على معلومات المستخدم
            user_info = self._get_user_info(user_id)
            if not user_info:
                return None
            
            username = user_info['username']
            
            # إنشاء URI للمصادقة
            provisioning_uri = totp.provisioning_uri(
                name=f"{username}@{service_name}",
                issuer_name=f"البوابة الأمنية - {service_name}"
            )
            
            # إنشاء رمز QR
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # حفظ الصورة
            qr_filename = f"qr_{user_id}_{int(time.time())}.png"
            qr_path = os.path.join(
                os.path.dirname(self.db_path), 
                "qr_codes", 
                qr_filename
            )
            
            # إنشاء المجلد إن لم يكن موجوداً
            os.makedirs(os.path.dirname(qr_path), exist_ok=True)
            
            # إنشاء وحفظ الصورة
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_path)
            
            return qr_path
            
        except Exception as e:
            print(f"خطأ في إنشاء رمز QR: {e}")
            return None
    
    def verify_totp_code(self, user_id: str, code: str, 
                        telegram_uid: str = None, 
                        ip_address: str = None, 
                        user_agent: str = None) -> Dict[str, Any]:
        """
        التحقق من صحة رمز TOTP
        
        Args:
            user_id: معرف المستخدم
            code: الرمز المؤقت المدخل
            telegram_uid: معرف Telegram (للتحقق الإضافي)
            ip_address: عنوان IP للمحاولة
            user_agent: معلومات المتصفح
            
        Returns:
            نتيجة التحقق مع التفاصيل
        """
        result = {
            'success': False,
            'message': '',
            'user_locked': False,
            'remaining_attempts': 0,
            'lockout_time': None
        }
        
        try:
            # التحقق من حالة المستخدم
            user_status = self._check_user_status(user_id)
            if not user_status['active']:
                result['message'] = user_status['message']
                result['user_locked'] = user_status.get('locked', False)
                result['lockout_time'] = user_status.get('lockout_time')
                self._log_auth_attempt(user_id, telegram_uid, False, 
                                     ip_address, user_agent, result['message'])
                return result
            
            # استرجاع السر المشترك
            secret = self._get_user_secret(user_id)
            if not secret:
                result['message'] = 'المستخدم غير موجود أو غير مفعل'
                self._log_auth_attempt(user_id, telegram_uid, False, 
                                     ip_address, user_agent, result['message'])
                return result
            
            # التحقق من معرف Telegram إن قُدم
            if telegram_uid:
                user_info = self._get_user_info(user_id)
                if user_info and user_info['telegram_uid'] != telegram_uid:
                    result['message'] = 'معرف Telegram غير متطابق'
                    self._log_auth_attempt(user_id, telegram_uid, False, 
                                         ip_address, user_agent, result['message'])
                    return result
            
            # إنشاء TOTP وتحقق من الرمز
            totp = pyotp.TOTP(secret)
            
            # السماح بانحراف زمني قدره 30 ثانية في كلا الاتجاهين
            is_valid = totp.verify(code, valid_window=1)
            
            if is_valid:
                # نجحت المصادقة
                self._reset_failed_attempts(user_id)
                self._update_last_used(user_id)
                result['success'] = True
                result['message'] = 'تم التحقق بنجاح'
                self._log_auth_attempt(user_id, telegram_uid, True, 
                                     ip_address, user_agent, 'نجحت المصادقة')
            else:
                # فشلت المصادقة
                self._increment_failed_attempts(user_id)
                user_status = self._check_user_status(user_id)
                result['message'] = 'رمز المصادقة غير صحيح'
                result['remaining_attempts'] = max(0, 5 - user_status.get('failed_attempts', 0))
                result['user_locked'] = user_status.get('locked', False)
                result['lockout_time'] = user_status.get('lockout_time')
                self._log_auth_attempt(user_id, telegram_uid, False, 
                                     ip_address, user_agent, result['message'])
            
            return result
            
        except Exception as e:
            result['message'] = f'خطأ في التحقق: {str(e)}'
            self._log_auth_attempt(user_id, telegram_uid, False, 
                                 ip_address, user_agent, result['message'])
            return result
    
    def _get_user_secret(self, user_id: str) -> Optional[str]:
        """استرجاع السر المشترك للمستخدم"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT encrypted_secret FROM user_secrets WHERE user_id = ? AND is_active = 1',
                    (user_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    encrypted_secret = row[0].encode()
                    secret = self.cipher_suite.decrypt(encrypted_secret).decode()
                    return secret
                return None
                
        except Exception as e:
            print(f"خطأ في استرجاع السر المشترك: {e}")
            return None
    
    def _get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع معلومات المستخدم"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT telegram_uid, username, created_at, last_used, failed_attempts
                    FROM user_secrets 
                    WHERE user_id = ? AND is_active = 1
                ''', (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'telegram_uid': row[0],
                        'username': row[1],
                        'created_at': row[2],
                        'last_used': row[3],
                        'failed_attempts': row[4]
                    }
                return None
                
        except Exception as e:
            print(f"خطأ في استرجاع معلومات المستخدم: {e}")
            return None
    
    def _check_user_status(self, user_id: str) -> Dict[str, Any]:
        """التحقق من حالة المستخدم والقفل"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT is_active, failed_attempts, locked_until
                    FROM user_secrets 
                    WHERE user_id = ?
                ''', (user_id,))
                row = cursor.fetchone()
                
                if not row:
                    return {'active': False, 'message': 'المستخدم غير موجود'}
                
                is_active, failed_attempts, locked_until = row
                
                if not is_active:
                    return {'active': False, 'message': 'الحساب غير مفعل'}
                
                # التحقق من القفل الزمني
                if locked_until:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        return {
                            'active': False, 
                            'locked': True,
                            'message': f'الحساب مقفل حتى {lock_time.strftime("%Y-%m-%d %H:%M:%S")}',
                            'lockout_time': locked_until
                        }
                    else:
                        # انتهى وقت القفل، إعادة تعيين
                        conn.execute(
                            'UPDATE user_secrets SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?',
                            (user_id,)
                        )
                        conn.commit()
                
                return {
                    'active': True, 
                    'failed_attempts': failed_attempts,
                    'message': 'الحساب نشط'
                }
                
        except Exception as e:
            print(f"خطأ في التحقق من حالة المستخدم: {e}")
            return {'active': False, 'message': f'خطأ: {str(e)}'}
    
    def _increment_failed_attempts(self, user_id: str):
        """زيادة عداد المحاولات الفاشلة"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # زيادة العداد
                conn.execute(
                    'UPDATE user_secrets SET failed_attempts = failed_attempts + 1 WHERE user_id = ?',
                    (user_id,)
                )
                
                # التحقق من تجاوز الحد الأقصى
                cursor = conn.execute(
                    'SELECT failed_attempts FROM user_secrets WHERE user_id = ?',
                    (user_id,)
                )
                row = cursor.fetchone()
                
                if row and row[0] >= 5:  # الحد الأقصى 5 محاولات
                    # قفل الحساب لمدة 30 دقيقة
                    lockout_time = datetime.now() + timedelta(minutes=30)
                    conn.execute(
                        'UPDATE user_secrets SET locked_until = ? WHERE user_id = ?',
                        (lockout_time.isoformat(), user_id)
                    )
                
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تحديث المحاولات الفاشلة: {e}")
    
    def _reset_failed_attempts(self, user_id: str):
        """إعادة تعيين عداد المحاولات الفاشلة"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE user_secrets SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?',
                    (user_id,)
                )
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في إعادة تعيين المحاولات الفاشلة: {e}")
    
    def _update_last_used(self, user_id: str):
        """تحديث وقت آخر استخدام"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE user_secrets SET last_used = CURRENT_TIMESTAMP WHERE user_id = ?',
                    (user_id,)
                )
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تحديث وقت آخر استخدام: {e}")
    
    def _log_auth_attempt(self, user_id: str, telegram_uid: str, success: bool, 
                         ip_address: str = None, user_agent: str = None, 
                         error_message: str = None):
        """تسجيل محاولة المصادقة"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO auth_attempts 
                    (user_id, telegram_uid, success, ip_address, user_agent, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, telegram_uid or '', success, ip_address or '', 
                      user_agent or '', error_message or ''))
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تسجيل محاولة المصادقة: {e}")
    
    def get_backup_codes(self, user_id: str) -> Optional[list]:
        """استرجاع رموز النسخ الاحتياطية للمستخدم"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT backup_codes FROM user_secrets WHERE user_id = ? AND is_active = 1',
                    (user_id,)
                )
                row = cursor.fetchone()
                
                if row and row[0]:
                    encrypted_codes = row[0].encode()
                    codes_json = self.cipher_suite.decrypt(encrypted_codes).decode()
                    return json.loads(codes_json)
                return None
                
        except Exception as e:
            print(f"خطأ في استرجاع رموز النسخ الاحتياطية: {e}")
            return None
    
    def verify_backup_code(self, user_id: str, backup_code: str) -> bool:
        """التحقق من رمز النسخ الاحتياطي واستخدامه"""
        try:
            backup_codes = self.get_backup_codes(user_id)
            if not backup_codes:
                return False
            
            if backup_code in backup_codes:
                # إزالة الرمز المستخدم
                backup_codes.remove(backup_code)
                
                # حفظ القائمة المحدثة
                encrypted_codes = self.cipher_suite.encrypt(
                    json.dumps(backup_codes).encode()
                )
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        'UPDATE user_secrets SET backup_codes = ? WHERE user_id = ?',
                        (encrypted_codes.decode(), user_id)
                    )
                    conn.commit()
                
                # إعادة تعيين المحاولات الفاشلة
                self._reset_failed_attempts(user_id)
                self._update_last_used(user_id)
                
                return True
            
            return False
            
        except Exception as e:
            print(f"خطأ في التحقق من رمز النسخ الاحتياطي: {e}")
            return False
    
    def deactivate_user(self, user_id: str) -> bool:
        """إلغاء تفعيل المستخدم"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE user_secrets SET is_active = 0 WHERE user_id = ?',
                    (user_id,)
                )
                conn.commit()
                return True
                
        except Exception as e:
            print(f"خطأ في إلغاء تفعيل المستخدم: {e}")
            return False
    
    def get_auth_statistics(self, user_id: str = None, days: int = 30) -> Dict[str, Any]:
        """الحصول على إحصائيات المصادقة"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # تحديد الفترة الزمنية
                since_date = datetime.now() - timedelta(days=days)
                
                if user_id:
                    # إحصائيات مستخدم محدد
                    cursor = conn.execute('''
                        SELECT 
                            COUNT(*) as total_attempts,
                            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_attempts,
                            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_attempts
                        FROM auth_attempts 
                        WHERE user_id = ? AND attempt_time >= ?
                    ''', (user_id, since_date.isoformat()))
                else:
                    # إحصائيات عامة
                    cursor = conn.execute('''
                        SELECT 
                            COUNT(*) as total_attempts,
                            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_attempts,
                            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_attempts
                        FROM auth_attempts 
                        WHERE attempt_time >= ?
                    ''', (since_date.isoformat(),))
                
                row = cursor.fetchone()
                
                if row:
                    total, successful, failed = row
                    return {
                        'total_attempts': total or 0,
                        'successful_attempts': successful or 0,
                        'failed_attempts': failed or 0,
                        'success_rate': (successful / total * 100) if total > 0 else 0,
                        'period_days': days
                    }
                
                return {
                    'total_attempts': 0,
                    'successful_attempts': 0,
                    'failed_attempts': 0,
                    'success_rate': 0,
                    'period_days': days
                }
                
        except Exception as e:
            print(f"خطأ في جلب الإحصائيات: {e}")
            return {}


def main():
    """
    دالة اختبار أساسية لمدير Google Authenticator
    """
    print("اختبار مدير Google Authenticator...")
    
    # إنشاء مثيل من المدير
    auth_manager = GoogleAuthenticatorManager()
    
    # اختبار توليد سر مشترك
    user_id = "test_user_001"
    telegram_uid = "123456789"
    username = "مستخدم_اختبار"
    
    print(f"توليد سر مشترك للمستخدم: {username}")
    secret = auth_manager.generate_secret_key(user_id, telegram_uid, username)
    print(f"السر المولد: {secret}")
    
    # اختبار إنشاء رمز QR
    print("إنشاء رمز QR...")
    qr_path = auth_manager.generate_qr_code(user_id, "مسرور")
    if qr_path:
        print(f"تم إنشاء رمز QR: {qr_path}")
    else:
        print("فشل في إنشاء رمز QR")
    
    # اختبار التحقق من الرمز
    print("اختبار التحقق من الرمز...")
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    print(f"الرمز الحالي: {current_code}")
    
    # التحقق من الرمز
    result = auth_manager.verify_totp_code(user_id, current_code, telegram_uid)
    print(f"نتيجة التحقق: {result}")
    
    # اختبار رموز النسخ الاحتياطية
    backup_codes = auth_manager.get_backup_codes(user_id)
    if backup_codes:
        print(f"رموز النسخ الاحتياطية: {backup_codes}")
        
        # اختبار استخدام رمز احتياطي
        test_backup = backup_codes[0]
        backup_result = auth_manager.verify_backup_code(user_id, test_backup)
        print(f"نتيجة التحقق من الرمز الاحتياطي: {backup_result}")
    
    # الحصول على الإحصائيات
    stats = auth_manager.get_auth_statistics(user_id)
    print(f"إحصائيات المصادقة: {stats}")
    
    print("انتهى الاختبار.")


if __name__ == "__main__":
    main()