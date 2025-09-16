#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
البوابة الأمنية لمنظومة مسرور - التوقيع الرقمي والتحقق
================================================

هذا الملف يحتوي على وظائف التوقيع الرقمي والتحقق من الرسائل مع الطوابع الزمنية
لضمان سلامة وصحة البيانات في بوابة الأمان لمنظومة مسرور.

المتطلبات:
- cryptography: للتوقيع الرقمي والتشفير
- datetime: للطوابع الزمنية
- hashlib: للتدقيق والأمان

المؤلف: منظومة مسرور
التاريخ: 2024
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
import json
import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, Union
import sqlite3
import os


class DigitalSignatureManager:
    """
    مدير التوقيع الرقمي والتحقق من الرسائل
    
    يوفر وظائف:
    - توليد أزواج المفاتيح العامة والخاصة
    - التوقيع الرقمي للرسائل
    - التحقق من التوقيعات
    - إدارة الطوابع الزمنية
    - حماية سلامة البيانات
    """
    
    def __init__(self, db_path: str = "مسرور_signatures.db", key_size: int = 2048):
        """
        تهيئة مدير التوقيع الرقمي
        
        Args:
            db_path: مسار قاعدة البيانات
            key_size: حجم المفتاح (2048 أو 4096)
        """
        self.db_path = db_path
        self.key_size = key_size
        self.backend = default_backend()
        self._init_database()
    
    def _init_database(self):
        """تهيئة قاعدة البيانات وإنشاء الجداول المطلوبة"""
        with sqlite3.connect(self.db_path) as conn:
            # جدول المفاتيح
            conn.execute('''
                CREATE TABLE IF NOT EXISTS keypairs (
                    key_id TEXT PRIMARY KEY,
                    entity_name TEXT NOT NULL,
                    entity_type TEXT NOT NULL,  -- user, system, service
                    public_key TEXT NOT NULL,
                    private_key_encrypted TEXT NOT NULL,
                    passphrase_hash TEXT NOT NULL,
                    key_algorithm TEXT DEFAULT 'RSA-2048',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    usage_count INTEGER DEFAULT 0
                )
            ''')
            
            # جدول التوقيعات
            conn.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    signature_id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    message_hash TEXT NOT NULL,
                    signature_value TEXT NOT NULL,
                    timestamp_signed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message_type TEXT,
                    metadata TEXT,
                    verified_count INTEGER DEFAULT 0,
                    last_verified TIMESTAMP,
                    is_valid BOOLEAN DEFAULT 1,
                    FOREIGN KEY (key_id) REFERENCES keypairs (key_id)
                )
            ''')
            
            # جدول سجل التحقق
            conn.execute('''
                CREATE TABLE IF NOT EXISTS verification_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT NOT NULL,
                    verifier_info TEXT,
                    verification_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verification_result BOOLEAN NOT NULL,
                    error_message TEXT,
                    FOREIGN KEY (signature_id) REFERENCES signatures (signature_id)
                )
            ''')
            
            # الفهارس
            conn.execute('CREATE INDEX IF NOT EXISTS idx_signatures_key_id ON signatures(key_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_signatures_timestamp ON signatures(timestamp_signed)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_verification_log_signature ON verification_log(signature_id)')
            
            conn.commit()
    
    def generate_keypair(self, entity_name: str, entity_type: str = "user", 
                        expires_days: int = 365, passphrase: str = None) -> str:
        """
        توليد زوج مفاتيح جديد للتوقيع الرقمي
        
        Args:
            entity_name: اسم الكيان (مستخدم، نظام، خدمة)
            entity_type: نوع الكيان
            expires_days: عدد أيام انتهاء الصلاحية
            passphrase: كلمة مرور لحماية المفتاح الخاص
            
        Returns:
            معرف المفتاح المولد
        """
        try:
            # توليد المفتاح الخاص
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=self.backend
            )
            
            # استخراج المفتاح العام
            public_key = private_key.public_key()
            
            # تسلسل المفتاح العام
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # تسلسل المفتاح الخاص مع التشفير
            if passphrase:
                encryption_algorithm = serialization.BestAvailableEncryption(
                    passphrase.encode('utf-8')
                )
            else:
                # توليد كلمة مرور عشوائية
                passphrase = secrets.token_urlsafe(32)
                encryption_algorithm = serialization.BestAvailableEncryption(
                    passphrase.encode('utf-8')
                )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ).decode('utf-8')
            
            # إنشاء معرف فريد للمفتاح
            key_id = f"key_{entity_type}_{int(time.time())}_{secrets.token_hex(8)}"
            
            # حساب تاريخ انتهاء الصلاحية
            expires_at = datetime.now() + timedelta(days=expires_days)
            
            # حفظ في قاعدة البيانات
            with sqlite3.connect(self.db_path) as conn:
                # تشفير كلمة المرور للحفظ
                passphrase_hash = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
                
                conn.execute('''
                    INSERT INTO keypairs 
                    (key_id, entity_name, entity_type, public_key, private_key_encrypted, 
                     passphrase_hash, key_algorithm, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (key_id, entity_name, entity_type, public_pem, private_pem,
                      passphrase_hash, f"RSA-{self.key_size}", expires_at.isoformat()))
                conn.commit()
            
            # إرجاع معرف المفتاح وكلمة المرور
            return {
                'key_id': key_id,
                'passphrase': passphrase  # إرجاع كلمة المرور دائماً
            }
            
        except Exception as e:
            print(f"خطأ في توليد زوج المفاتيح: {e}")
            return None
    
    def sign_message(self, key_id: str, message: Union[str, bytes], 
                    message_type: str = "general", metadata: Dict = None,
                    passphrase: str = None) -> Optional[str]:
        """
        توقيع رسالة رقمياً
        
        Args:
            key_id: معرف المفتاح
            message: الرسالة المراد توقيعها
            message_type: نوع الرسالة
            metadata: معلومات إضافية
            passphrase: كلمة مرور المفتاح الخاص
            
        Returns:
            معرف التوقيع أو None في حالة الخطأ
        """
        try:
            # الحصول على المفتاح الخاص
            private_key = self._get_private_key(key_id, passphrase)
            if not private_key:
                return None
            
            # تحويل الرسالة إلى bytes إذا لزم الأمر
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # حساب hash للرسالة
            message_hash = hashlib.sha256(message_bytes).hexdigest()
            
            # إنشاء الطابع الزمني
            timestamp = datetime.now()
            
            # إنشاء البيانات المراد توقيعها (رسالة + طابع زمني)
            signing_data = {
                'message_hash': message_hash,
                'timestamp': timestamp.isoformat(),
                'message_type': message_type,
                'metadata': metadata or {}
            }
            signing_bytes = json.dumps(signing_data, sort_keys=True).encode('utf-8')
            
            # إنشاء التوقيع
            signature = private_key.sign(
                signing_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # تحويل التوقيع إلى base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # إنشاء معرف فريد للتوقيع
            signature_id = f"sig_{int(time.time())}_{secrets.token_hex(8)}"
            
            # حفظ التوقيع في قاعدة البيانات
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO signatures 
                    (signature_id, key_id, message_hash, signature_value, 
                     timestamp_signed, message_type, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (signature_id, key_id, message_hash, signature_b64,
                      timestamp.isoformat(), message_type, 
                      json.dumps(metadata) if metadata else None))
                
                # تحديث عداد استخدام المفتاح
                conn.execute(
                    'UPDATE keypairs SET usage_count = usage_count + 1 WHERE key_id = ?',
                    (key_id,)
                )
                
                conn.commit()
            
            return signature_id
            
        except Exception as e:
            print(f"خطأ في توقيع الرسالة: {e}")
            return None
    
    def verify_signature(self, signature_id: str, message: Union[str, bytes],
                        verifier_info: str = None) -> Dict[str, Any]:
        """
        التحقق من صحة التوقيع الرقمي
        
        Args:
            signature_id: معرف التوقيع
            message: الرسالة الأصلية
            verifier_info: معلومات المتحقق
            
        Returns:
            نتيجة التحقق مع التفاصيل
        """
        result = {
            'valid': False,
            'message': '',
            'signature_info': {},
            'timestamp_valid': False,
            'key_valid': False
        }
        
        try:
            # الحصول على معلومات التوقيع
            signature_info = self._get_signature_info(signature_id)
            if not signature_info:
                result['message'] = 'التوقيع غير موجود'
                return result
            
            result['signature_info'] = signature_info
            
            # التحقق من صحة المفتاح
            key_valid = self._is_key_valid(signature_info['key_id'])
            result['key_valid'] = key_valid
            
            if not key_valid:
                result['message'] = 'المفتاح غير صالح أو منتهي الصلاحية'
                self._log_verification(signature_id, verifier_info, False, result['message'])
                return result
            
            # الحصول على المفتاح العام
            public_key = self._get_public_key(signature_info['key_id'])
            if not public_key:
                result['message'] = 'لا يمكن الحصول على المفتاح العام'
                self._log_verification(signature_id, verifier_info, False, result['message'])
                return result
            
            # تحويل الرسالة إلى bytes
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            else:
                message_bytes = message
            
            # حساب hash للرسالة
            message_hash = hashlib.sha256(message_bytes).hexdigest()
            
            # التحقق من تطابق hash الرسالة
            if message_hash != signature_info['message_hash']:
                result['message'] = 'الرسالة لا تطابق التوقيع'
                self._log_verification(signature_id, verifier_info, False, result['message'])
                return result
            
            # إعادة بناء البيانات المطلوب التحقق منها
            signing_data = {
                'message_hash': signature_info['message_hash'],
                'timestamp': signature_info['timestamp_signed'],
                'message_type': signature_info['message_type'],
                'metadata': json.loads(signature_info['metadata']) if signature_info['metadata'] else {}
            }
            signing_bytes = json.dumps(signing_data, sort_keys=True).encode('utf-8')
            
            # تحويل التوقيع من base64
            signature_bytes = base64.b64decode(signature_info['signature_value'])
            
            # التحقق من التوقيع
            try:
                public_key.verify(
                    signature_bytes,
                    signing_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # التحقق من الطابع الزمني
                timestamp_check = self._verify_timestamp(signature_info['timestamp_signed'])
                result['timestamp_valid'] = timestamp_check['valid']
                
                if timestamp_check['valid']:
                    result['valid'] = True
                    result['message'] = 'التوقيع صحيح ومعتمد'
                else:
                    result['valid'] = False
                    result['message'] = f"التوقيع صحيح لكن الطابع الزمني غير معتمد: {timestamp_check['reason']}"
                
                # تحديث الإحصائيات
                self._update_verification_stats(signature_id)
                self._log_verification(signature_id, verifier_info, result['valid'], result['message'])
                
                return result
                
            except InvalidSignature:
                result['message'] = 'التوقيع الرقمي غير صحيح'
                self._log_verification(signature_id, verifier_info, False, result['message'])
                return result
            
        except Exception as e:
            result['message'] = f'خطأ في التحقق من التوقيع: {str(e)}'
            self._log_verification(signature_id, verifier_info, False, result['message'])
            return result
    
    def _get_private_key(self, key_id: str, passphrase: str = None):
        """استرجاع المفتاح الخاص"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT private_key_encrypted, passphrase_hash FROM keypairs WHERE key_id = ? AND is_active = 1',
                    (key_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                private_pem, stored_passphrase_hash = row
                
                # إذا لم تُقدم كلمة المرور، نحتاج للبحث عنها
                if passphrase is None:
                    print(f"خطأ: كلمة مرور المفتاح الخاص مطلوبة للمفتاح {key_id}")
                    return None
                
                # التحقق من كلمة المرور
                provided_hash = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
                if provided_hash != stored_passphrase_hash:
                    print("خطأ: كلمة المرور غير صحيحة")
                    return None
                
                # تحميل المفتاح الخاص
                private_key = serialization.load_pem_private_key(
                    private_pem.encode('utf-8'),
                    password=passphrase.encode('utf-8'),
                    backend=self.backend
                )
                
                return private_key
                
        except Exception as e:
            print(f"خطأ في استرجاع المفتاح الخاص: {e}")
            return None
    
    def _get_public_key(self, key_id: str):
        """استرجاع المفتاح العام"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT public_key FROM keypairs WHERE key_id = ? AND is_active = 1',
                    (key_id,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                public_pem = row[0]
                
                # تحميل المفتاح العام
                public_key = serialization.load_pem_public_key(
                    public_pem.encode('utf-8'),
                    backend=self.backend
                )
                
                return public_key
                
        except Exception as e:
            print(f"خطأ في استرجاع المفتاح العام: {e}")
            return None
    
    def _get_signature_info(self, signature_id: str) -> Optional[Dict[str, Any]]:
        """الحصول على معلومات التوقيع"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT key_id, message_hash, signature_value, timestamp_signed, 
                           message_type, metadata, verified_count, is_valid
                    FROM signatures 
                    WHERE signature_id = ?
                ''', (signature_id,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'key_id': row[0],
                        'message_hash': row[1],
                        'signature_value': row[2],
                        'timestamp_signed': row[3],
                        'message_type': row[4],
                        'metadata': row[5],
                        'verified_count': row[6],
                        'is_valid': row[7]
                    }
                return None
                
        except Exception as e:
            print(f"خطأ في الحصول على معلومات التوقيع: {e}")
            return None
    
    def _is_key_valid(self, key_id: str) -> bool:
        """التحقق من صحة المفتاح"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT expires_at, is_active 
                    FROM keypairs 
                    WHERE key_id = ?
                ''', (key_id,))
                row = cursor.fetchone()
                
                if not row:
                    return False
                
                expires_at, is_active = row
                
                if not is_active:
                    return False
                
                # التحقق من انتهاء الصلاحية
                if expires_at:
                    expiry_date = datetime.fromisoformat(expires_at)
                    if datetime.now() > expiry_date:
                        return False
                
                return True
                
        except Exception as e:
            print(f"خطأ في التحقق من صحة المفتاح: {e}")
            return False
    
    def _verify_timestamp(self, timestamp_str: str, max_age_hours: int = 24) -> Dict[str, Any]:
        """التحقق من صحة الطابع الزمني"""
        try:
            signature_time = datetime.fromisoformat(timestamp_str)
            current_time = datetime.now()
            
            # التحقق من أن التوقيع ليس في المستقبل
            if signature_time > current_time:
                return {
                    'valid': False,
                    'reason': 'الطابع الزمني في المستقبل'
                }
            
            # التحقق من العمر الأقصى للتوقيع
            age = current_time - signature_time
            max_age = timedelta(hours=max_age_hours)
            
            if age > max_age:
                return {
                    'valid': False,
                    'reason': f'التوقيع قديم جداً (عمره {age.total_seconds() / 3600:.1f} ساعة)'
                }
            
            return {
                'valid': True,
                'reason': 'الطابع الزمني صحيح'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'reason': f'خطأ في التحقق من الطابع الزمني: {str(e)}'
            }
    
    def _update_verification_stats(self, signature_id: str):
        """تحديث إحصائيات التحقق"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE signatures 
                    SET verified_count = verified_count + 1, last_verified = CURRENT_TIMESTAMP
                    WHERE signature_id = ?
                ''', (signature_id,))
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تحديث إحصائيات التحقق: {e}")
    
    def _log_verification(self, signature_id: str, verifier_info: str, 
                         success: bool, message: str):
        """تسجيل محاولة التحقق"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO verification_log 
                    (signature_id, verifier_info, verification_result, error_message)
                    VALUES (?, ?, ?, ?)
                ''', (signature_id, verifier_info or '', success, 
                      message if not success else None))
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تسجيل محاولة التحقق: {e}")
    
    def create_timestamped_message(self, message: Union[str, Dict], 
                                  message_type: str = "general") -> Dict[str, Any]:
        """
        إنشاء رسالة مع طابع زمني محقق
        
        Args:
            message: الرسالة الأصلية
            message_type: نوع الرسالة
            
        Returns:
            الرسالة مع الطابع الزمني والتحقق
        """
        timestamp = datetime.now()
        
        # إنشاء الرسالة مع الطابع الزمني
        timestamped_message = {
            'content': message,
            'timestamp': timestamp.isoformat(),
            'message_type': message_type,
            'nonce': secrets.token_hex(16),  # منع إعادة الإرسال
            'hash': None
        }
        
        # حساب hash للرسالة
        message_str = json.dumps(timestamped_message, sort_keys=True)
        message_hash = hashlib.sha256(message_str.encode('utf-8')).hexdigest()
        timestamped_message['hash'] = message_hash
        
        return timestamped_message
    
    def revoke_key(self, key_id: str, reason: str = "") -> bool:
        """
        إلغاء مفتاح وجعله غير صالح
        
        Args:
            key_id: معرف المفتاح
            reason: سبب الإلغاء
            
        Returns:
            True في حالة النجاح
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # إلغاء تفعيل المفتاح
                conn.execute(
                    'UPDATE keypairs SET is_active = 0 WHERE key_id = ?',
                    (key_id,)
                )
                
                # إلغاء تفعيل جميع التوقيعات المرتبطة
                conn.execute(
                    'UPDATE signatures SET is_valid = 0 WHERE key_id = ?',
                    (key_id,)
                )
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"خطأ في إلغاء المفتاح: {e}")
            return False
    
    def get_signature_statistics(self, key_id: str = None, days: int = 30) -> Dict[str, Any]:
        """الحصول على إحصائيات التوقيعات"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                since_date = datetime.now() - timedelta(days=days)
                
                if key_id:
                    # إحصائيات مفتاح محدد
                    cursor = conn.execute('''
                        SELECT 
                            COUNT(*) as total_signatures,
                            SUM(verified_count) as total_verifications,
                            AVG(verified_count) as avg_verifications_per_signature
                        FROM signatures 
                        WHERE key_id = ? AND timestamp_signed >= ?
                    ''', (key_id, since_date.isoformat()))
                else:
                    # إحصائيات عامة
                    cursor = conn.execute('''
                        SELECT 
                            COUNT(*) as total_signatures,
                            SUM(verified_count) as total_verifications,
                            AVG(verified_count) as avg_verifications_per_signature
                        FROM signatures 
                        WHERE timestamp_signed >= ?
                    ''', (since_date.isoformat(),))
                
                row = cursor.fetchone()
                
                if row:
                    total_sigs, total_verifs, avg_verifs = row
                    return {
                        'total_signatures': total_sigs or 0,
                        'total_verifications': total_verifs or 0,
                        'avg_verifications_per_signature': avg_verifs or 0,
                        'period_days': days
                    }
                
                return {
                    'total_signatures': 0,
                    'total_verifications': 0,
                    'avg_verifications_per_signature': 0,
                    'period_days': days
                }
                
        except Exception as e:
            print(f"خطأ في جلب إحصائيات التوقيعات: {e}")
            return {}


def main():
    """
    دالة اختبار أساسية لمدير التوقيع الرقمي
    """
    print("اختبار مدير التوقيع الرقمي...")
    
    # إنشاء مثيل من المدير
    signature_manager = DigitalSignatureManager()
    
    # اختبار توليد مفتاح
    entity_name = "نظام_مسرور_الأمني"
    print(f"توليد مفتاح للكيان: {entity_name}")
    key_result = signature_manager.generate_keypair(entity_name, "system")
    
    if key_result and isinstance(key_result, dict):
        key_id = key_result['key_id']
        passphrase = key_result['passphrase']
        print(f"تم توليد المفتاح بنجاح: {key_id}")
        
        # اختبار التوقيع
        test_message = "هذه رسالة اختبار للتوقيع الرقمي في منظومة مسرور"
        print(f"توقيع الرسالة: {test_message}")
        
        signature_id = signature_manager.sign_message(
            key_id, 
            test_message, 
            "test_message",
            {"source": "test_system", "priority": "high"},
            passphrase
        )
        
        if signature_id:
            print(f"تم التوقيع بنجاح: {signature_id}")
            
            # اختبار التحقق
            print("التحقق من التوقيع...")
            verification_result = signature_manager.verify_signature(
                signature_id, 
                test_message,
                "test_verifier"
            )
            
            print(f"نتيجة التحقق: {verification_result}")
            
            # اختبار إنشاء رسالة مع طابع زمني
            print("إنشاء رسالة مع طابع زمني...")
            timestamped_msg = signature_manager.create_timestamped_message(
                {"action": "login", "user": "test_user"}, 
                "auth_message"
            )
            print(f"الرسالة مع الطابع الزمني: {timestamped_msg}")
            
            # الحصول على الإحصائيات
            stats = signature_manager.get_signature_statistics(key_id)
            print(f"إحصائيات التوقيعات: {stats}")
            
        else:
            print("فشل في التوقيع")
    else:
        print("فشل في توليد المفتاح")
    
    print("انتهى الاختبار.")


if __name__ == "__main__":
    main()