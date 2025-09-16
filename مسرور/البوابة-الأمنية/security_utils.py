#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
البوابة الأمنية لمنظومة مسرور - أدوات الأمان المساعدة
============================================

هذا الملف يحتوي على وظائف مساعدة للأمان بما في ذلك إدارة المحاولات الفاشلة
وتطبيق آليات الحظر وحماية البوابة الأمنية لمنظومة مسرور.

المتطلبات:
- sqlite3: لتخزين بيانات الأمان
- datetime: لإدارة الأوقات
- hashlib: للتشفير والأمان
- secrets: لتوليد البيانات العشوائية الآمنة

المؤلف: منظومة مسرور
التاريخ: 2024
"""

import sqlite3
import hashlib
import secrets
import time
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from collections import defaultdict
import json
import bcrypt


class SecurityUtils:
    """
    أدوات الأمان المساعدة للبوابة الأمنية
    
    يوفر وظائف:
    - إدارة المحاولات الفاشلة
    - تطبيق آليات الحظر
    - مراقبة الأنشطة المشبوهة
    - حماية من الهجمات الشائعة
    - إدارة كلمات المرور الآمنة
    """
    
    def __init__(self, db_path: str = "مسرور_security_utils.db"):
        """
        تهيئة أدوات الأمان
        
        Args:
            db_path: مسار قاعدة البيانات
        """
        self.db_path = db_path
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        self.suspicious_activity_threshold = 10
        self.rate_limit_window_minutes = 15
        self.max_requests_per_window = 100
        self._init_database()
    
    def _init_database(self):
        """تهيئة قاعدة البيانات وإنشاء الجداول المطلوبة"""
        with sqlite3.connect(self.db_path) as conn:
            # جدول المحاولات الفاشلة
            conn.execute('''
                CREATE TABLE IF NOT EXISTS failed_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT NOT NULL,  -- user_id, IP, etc.
                    identifier_type TEXT NOT NULL,  -- user, ip, telegram_uid
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    attempt_type TEXT NOT NULL,  -- login, api_call, etc.
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    severity INTEGER DEFAULT 1  -- 1=low, 2=medium, 3=high, 4=critical
                )
            ''')
            
            # جدول الحظر النشط
            conn.execute('''
                CREATE TABLE IF NOT EXISTS active_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT NOT NULL,
                    identifier_type TEXT NOT NULL,
                    blocked_until TIMESTAMP NOT NULL,
                    block_reason TEXT NOT NULL,
                    block_level INTEGER DEFAULT 1,  -- 1=temporary, 2=extended, 3=permanent
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # جدول الأنشطة المشبوهة
            conn.execute('''
                CREATE TABLE IF NOT EXISTS suspicious_activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT NOT NULL,
                    identifier_type TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    details TEXT,
                    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT 0,
                    resolver_notes TEXT
                )
            ''')
            
            # جدول حدود المعدل (Rate Limiting)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT NOT NULL,
                    identifier_type TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    window_start TIMESTAMP NOT NULL,
                    last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # جدول كلمات المرور المحظورة
            conn.execute('''
                CREATE TABLE IF NOT EXISTS banned_passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # جدول سجل الأمان
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    identifier TEXT,
                    identifier_type TEXT,
                    event_data TEXT,
                    severity INTEGER DEFAULT 1,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    resolved BOOLEAN DEFAULT 0
                )
            ''')
            
            # الفهارس
            conn.execute('CREATE INDEX IF NOT EXISTS idx_failed_attempts_identifier ON failed_attempts(identifier, identifier_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_failed_attempts_time ON failed_attempts(attempt_time)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_active_blocks_identifier ON active_blocks(identifier, identifier_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_suspicious_activities_identifier ON suspicious_activities(identifier, identifier_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, identifier_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_security_log_type ON security_log(event_type, timestamp)')
            
            conn.commit()
    
    def record_failed_attempt(self, identifier: str, identifier_type: str, 
                            attempt_type: str, ip_address: str = None,
                            user_agent: str = None, details: str = None,
                            severity: int = 1) -> Dict[str, Any]:
        """
        تسجيل محاولة فاشلة
        
        Args:
            identifier: المعرف (مستخدم، IP، إلخ)
            identifier_type: نوع المعرف
            attempt_type: نوع المحاولة
            ip_address: عنوان IP
            user_agent: معلومات المتصفح
            details: تفاصيل إضافية
            severity: مستوى الخطورة
            
        Returns:
            معلومات عن حالة الحظر
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # تسجيل المحاولة الفاشلة
                conn.execute('''
                    INSERT INTO failed_attempts 
                    (identifier, identifier_type, attempt_type, ip_address, user_agent, details, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (identifier, identifier_type, attempt_type, ip_address or '', 
                      user_agent or '', details or '', severity))
                
                # حساب عدد المحاولات الفاشلة الحديثة
                since_time = datetime.now() - timedelta(hours=1)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM failed_attempts 
                    WHERE identifier = ? AND identifier_type = ? AND attempt_time >= ?
                ''', (identifier, identifier_type, since_time.isoformat()))
                
                attempt_count = cursor.fetchone()[0]
                
                # تحديد ما إذا كان يجب تطبيق الحظر
                should_block = attempt_count >= self.max_login_attempts
                block_info = None
                
                if should_block:
                    block_info = self._apply_block(
                        identifier, identifier_type, 
                        f"تجاوز الحد الأقصى للمحاولات الفاشلة ({attempt_count})",
                        severity
                    )
                
                # تسجيل في سجل الأمان
                self._log_security_event(
                    "failed_attempt",
                    identifier,
                    identifier_type,
                    {
                        "attempt_type": attempt_type,
                        "attempt_count": attempt_count,
                        "blocked": should_block,
                        "details": details
                    },
                    severity,
                    ip_address
                )
                
                conn.commit()
                
                return {
                    "attempt_count": attempt_count,
                    "blocked": should_block,
                    "block_info": block_info,
                    "max_attempts": self.max_login_attempts
                }
                
        except Exception as e:
            print(f"خطأ في تسجيل المحاولة الفاشلة: {e}")
            return {"error": str(e)}
    
    def check_block_status(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """
        التحقق من حالة الحظر
        
        Args:
            identifier: المعرف
            identifier_type: نوع المعرف
            
        Returns:
            معلومات حالة الحظر
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT blocked_until, block_reason, block_level, created_at
                    FROM active_blocks 
                    WHERE identifier = ? AND identifier_type = ? 
                    AND is_active = 1 AND blocked_until > datetime('now')
                    ORDER BY created_at DESC LIMIT 1
                ''', (identifier, identifier_type))
                
                row = cursor.fetchone()
                
                if row:
                    blocked_until, reason, level, created_at = row
                    block_time = datetime.fromisoformat(blocked_until)
                    remaining_time = block_time - datetime.now()
                    
                    return {
                        "blocked": True,
                        "blocked_until": blocked_until,
                        "reason": reason,
                        "block_level": level,
                        "remaining_minutes": max(0, int(remaining_time.total_seconds() / 60)),
                        "created_at": created_at
                    }
                else:
                    # تنظيف الحظر المنتهي الصلاحية
                    conn.execute('''
                        UPDATE active_blocks 
                        SET is_active = 0 
                        WHERE identifier = ? AND identifier_type = ? 
                        AND blocked_until <= datetime('now')
                    ''', (identifier, identifier_type))
                    conn.commit()
                    
                    return {"blocked": False}
                
        except Exception as e:
            print(f"خطأ في التحقق من حالة الحظر: {e}")
            return {"error": str(e)}
    
    def _apply_block(self, identifier: str, identifier_type: str, 
                    reason: str, severity: int = 1) -> Dict[str, Any]:
        """تطبيق الحظر"""
        try:
            # تحديد مدة الحظر بناءً على الخطورة والتاريخ
            duration_minutes = self._calculate_block_duration(identifier, identifier_type, severity)
            blocked_until = datetime.now() + timedelta(minutes=duration_minutes)
            
            # تحديد مستوى الحظر
            block_level = min(3, severity)
            
            with sqlite3.connect(self.db_path) as conn:
                # إلغاء تفعيل الحظر السابق
                conn.execute('''
                    UPDATE active_blocks 
                    SET is_active = 0 
                    WHERE identifier = ? AND identifier_type = ?
                ''', (identifier, identifier_type))
                
                # إضافة حظر جديد
                conn.execute('''
                    INSERT INTO active_blocks 
                    (identifier, identifier_type, blocked_until, block_reason, block_level)
                    VALUES (?, ?, ?, ?, ?)
                ''', (identifier, identifier_type, blocked_until.isoformat(), reason, block_level))
                
                conn.commit()
                
                return {
                    "blocked_until": blocked_until.isoformat(),
                    "duration_minutes": duration_minutes,
                    "block_level": block_level,
                    "reason": reason
                }
                
        except Exception as e:
            print(f"خطأ في تطبيق الحظر: {e}")
            return {"error": str(e)}
    
    def _calculate_block_duration(self, identifier: str, identifier_type: str, 
                                severity: int) -> int:
        """حساب مدة الحظر بناءً على التاريخ والخطورة"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # حساب عدد الحظر السابق في آخر 24 ساعة
                since_time = datetime.now() - timedelta(hours=24)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM active_blocks 
                    WHERE identifier = ? AND identifier_type = ? AND created_at >= ?
                ''', (identifier, identifier_type, since_time.isoformat()))
                
                previous_blocks = cursor.fetchone()[0]
                
                # حساب المدة الأساسية
                base_duration = self.lockout_duration_minutes
                
                # زيادة المدة بناءً على التكرار
                multiplier = 1 + (previous_blocks * 0.5)
                
                # زيادة المدة بناءً على الخطورة
                severity_multiplier = severity
                
                # الحد الأقصى للحظر
                max_duration = 24 * 60  # 24 ساعة
                
                duration = min(int(base_duration * multiplier * severity_multiplier), max_duration)
                
                return duration
                
        except Exception as e:
            print(f"خطأ في حساب مدة الحظر: {e}")
            return self.lockout_duration_minutes
    
    def check_rate_limit(self, identifier: str, identifier_type: str, 
                        request_type: str = "general") -> Dict[str, Any]:
        """
        التحقق من حدود المعدل
        
        Args:
            identifier: المعرف
            identifier_type: نوع المعرف
            request_type: نوع الطلب
            
        Returns:
            معلومات حدود المعدل
        """
        try:
            current_time = datetime.now()
            window_start = current_time - timedelta(minutes=self.rate_limit_window_minutes)
            
            with sqlite3.connect(self.db_path) as conn:
                # البحث عن النافذة الزمنية الحالية
                cursor = conn.execute('''
                    SELECT id, request_count, window_start 
                    FROM rate_limits 
                    WHERE identifier = ? AND identifier_type = ? 
                    AND window_start >= ?
                    ORDER BY window_start DESC LIMIT 1
                ''', (identifier, identifier_type, window_start.isoformat()))
                
                row = cursor.fetchone()
                
                if row:
                    limit_id, request_count, existing_window_start = row
                    
                    # تحديث عداد الطلبات
                    new_count = request_count + 1
                    conn.execute('''
                        UPDATE rate_limits 
                        SET request_count = ?, last_request = ?
                        WHERE id = ?
                    ''', (new_count, current_time.isoformat(), limit_id))
                    
                    # التحقق من تجاوز الحد الأقصى
                    exceeded = new_count > self.max_requests_per_window
                    
                else:
                    # إنشاء نافذة جديدة
                    new_count = 1
                    conn.execute('''
                        INSERT INTO rate_limits 
                        (identifier, identifier_type, request_count, window_start)
                        VALUES (?, ?, ?, ?)
                    ''', (identifier, identifier_type, new_count, current_time.isoformat()))
                    
                    exceeded = False
                
                conn.commit()
                
                # إذا تم تجاوز الحد، تسجيل كنشاط مشبوه
                if exceeded:
                    self.record_suspicious_activity(
                        identifier, identifier_type, "rate_limit_exceeded",
                        3,  # خطورة متوسطة
                        f"تجاوز حد المعدل: {new_count} طلب في {self.rate_limit_window_minutes} دقيقة"
                    )
                
                return {
                    "allowed": not exceeded,
                    "current_count": new_count,
                    "max_requests": self.max_requests_per_window,
                    "window_minutes": self.rate_limit_window_minutes,
                    "reset_time": (current_time + timedelta(minutes=self.rate_limit_window_minutes)).isoformat()
                }
                
        except Exception as e:
            print(f"خطأ في التحقق من حدود المعدل: {e}")
            return {"error": str(e)}
    
    def record_suspicious_activity(self, identifier: str, identifier_type: str,
                                 activity_type: str, risk_score: int,
                                 details: str = None) -> bool:
        """
        تسجيل نشاط مشبوه
        
        Args:
            identifier: المعرف
            identifier_type: نوع المعرف
            activity_type: نوع النشاط
            risk_score: نقاط المخاطر (1-5)
            details: تفاصيل إضافية
            
        Returns:
            True في حالة النجاح
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO suspicious_activities 
                    (identifier, identifier_type, activity_type, risk_score, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (identifier, identifier_type, activity_type, risk_score, details or ''))
                
                # التحقق من تجاوز عتبة الأنشطة المشبوهة
                since_time = datetime.now() - timedelta(hours=24)
                cursor = conn.execute('''
                    SELECT COUNT(*), SUM(risk_score) 
                    FROM suspicious_activities 
                    WHERE identifier = ? AND identifier_type = ? 
                    AND detection_time >= ? AND resolved = 0
                ''', (identifier, identifier_type, since_time.isoformat()))
                
                count, total_risk = cursor.fetchone()
                
                # تطبيق حظر تلقائي إذا تجاوز العتبة
                if count >= self.suspicious_activity_threshold or (total_risk and total_risk >= 15):
                    self._apply_block(
                        identifier, identifier_type,
                        f"نشاط مشبوه مفرط: {count} حادثة، مجموع المخاطر: {total_risk}",
                        4  # خطورة عالية
                    )
                
                # تسجيل في سجل الأمان
                self._log_security_event(
                    "suspicious_activity",
                    identifier,
                    identifier_type,
                    {
                        "activity_type": activity_type,
                        "risk_score": risk_score,
                        "total_incidents": count,
                        "total_risk": total_risk,
                        "details": details
                    },
                    risk_score
                )
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"خطأ في تسجيل النشاط المشبوه: {e}")
            return False
    
    def validate_password_strength(self, password: str, username: str = None) -> Dict[str, Any]:
        """
        التحقق من قوة كلمة المرور
        
        Args:
            password: كلمة المرور
            username: اسم المستخدم (للتحقق من عدم التشابه)
            
        Returns:
            نتيجة التحقق من قوة كلمة المرور
        """
        result = {
            "valid": False,
            "score": 0,
            "issues": [],
            "suggestions": []
        }
        
        # التحقق من الطول الأدنى
        if len(password) < 8:
            result["issues"].append("كلمة المرور قصيرة جداً (أقل من 8 أحرف)")
            result["suggestions"].append("استخدم على الأقل 8 أحرف")
        elif len(password) >= 12:
            result["score"] += 2
        else:
            result["score"] += 1
        
        # التحقق من وجود أحرف كبيرة
        if not re.search(r'[A-Z]', password):
            result["issues"].append("لا تحتوي على أحرف كبيرة")
            result["suggestions"].append("أضف أحرف كبيرة (A-Z)")
        else:
            result["score"] += 1
        
        # التحقق من وجود أحرف صغيرة
        if not re.search(r'[a-z]', password):
            result["issues"].append("لا تحتوي على أحرف صغيرة")
            result["suggestions"].append("أضف أحرف صغيرة (a-z)")
        else:
            result["score"] += 1
        
        # التحقق من وجود أرقام
        if not re.search(r'\d', password):
            result["issues"].append("لا تحتوي على أرقام")
            result["suggestions"].append("أضف أرقام (0-9)")
        else:
            result["score"] += 1
        
        # التحقق من وجود رموز خاصة
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            result["issues"].append("لا تحتوي على رموز خاصة")
            result["suggestions"].append("أضف رموز خاصة (!@#$%^&*)")
        else:
            result["score"] += 1
        
        # التحقق من التشابه مع اسم المستخدم
        if username and username.lower() in password.lower():
            result["issues"].append("تحتوي على اسم المستخدم")
            result["suggestions"].append("تجنب استخدام اسم المستخدم في كلمة المرور")
            result["score"] -= 1
        
        # التحقق من الأنماط الشائعة
        common_patterns = [
            r'123456', r'password', r'qwerty', r'abc123',
            r'111111', r'123123', r'admin'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                result["issues"].append("تحتوي على نمط شائع ومكشوف")
                result["suggestions"].append("تجنب الأنماط الشائعة والمتسلسلة")
                result["score"] -= 2
                break
        
        # التحقق من كلمات المرور المحظورة
        if self._is_password_banned(password):
            result["issues"].append("كلمة مرور محظورة أو مكشوفة")
            result["suggestions"].append("استخدم كلمة مرور مختلفة تماماً")
            result["score"] -= 3
        
        # تحديد القوة العامة
        result["score"] = max(0, result["score"])
        
        if result["score"] >= 5 and len(result["issues"]) == 0:
            result["valid"] = True
            result["strength"] = "قوية جداً"
        elif result["score"] >= 4 and len(result["issues"]) <= 1:
            result["valid"] = True
            result["strength"] = "قوية"
        elif result["score"] >= 3:
            result["strength"] = "متوسطة"
        elif result["score"] >= 2:
            result["strength"] = "ضعيفة"
        else:
            result["strength"] = "ضعيفة جداً"
        
        return result
    
    def _is_password_banned(self, password: str) -> bool:
        """التحقق من كون كلمة المرور محظورة"""
        try:
            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT COUNT(*) FROM banned_passwords WHERE password_hash = ?',
                    (password_hash,)
                )
                return cursor.fetchone()[0] > 0
                
        except Exception as e:
            print(f"خطأ في التحقق من كلمة المرور المحظورة: {e}")
            return False
    
    def hash_password(self, password: str) -> str:
        """تشفير كلمة المرور بطريقة آمنة"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """التحقق من كلمة المرور"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            print(f"خطأ في التحقق من كلمة المرور: {e}")
            return False
    
    def validate_input(self, input_data: str, input_type: str = "general") -> Dict[str, Any]:
        """
        التحقق من صحة المدخلات وحمايتها من الهجمات
        
        Args:
            input_data: البيانات المدخلة
            input_type: نوع البيانات
            
        Returns:
            نتيجة التحقق والتنظيف
        """
        result = {
            "valid": True,
            "cleaned_data": input_data,
            "warnings": [],
            "blocked": False
        }
        
        # التحقق من SQL Injection
        sql_patterns = [
            r"(\'|(\'\')|(\-\-)|(\;)|(\|)|(\*)|(\%)|(\@)|(\#)|(\$)|(\^)|(\&)|(\+)|(\=)|(\<)|(\>)|(\?)|(\[)|(\])|(\{)|(\})|(\||(\n)|(\r)))",
            r"union.*select", r"insert.*into", r"delete.*from", r"drop.*table",
            r"exec.*\(", r"script.*\>", r"javascript:", r"vbscript:"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_data.lower()):
                result["warnings"].append("محتوى مشبوه قد يحتوي على SQL injection")
                result["blocked"] = True
                break
        
        # التحقق من XSS
        xss_patterns = [
            r"<script.*?>.*?</script>", r"javascript:", r"vbscript:",
            r"onload=", r"onerror=", r"onclick=", r"onmouseover=",
            r"<iframe.*?>", r"<object.*?>", r"<embed.*?>"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_data.lower()):
                result["warnings"].append("محتوى مشبوه قد يحتوي على XSS")
                result["blocked"] = True
                break
        
        # التحقق من Path Traversal
        if "../" in input_data or "..\\" in input_data:
            result["warnings"].append("محاولة path traversal")
            result["blocked"] = True
        
        # تنظيف البيانات حسب النوع
        if input_type == "username":
            # السماح فقط بالأحرف والأرقام والشرطة السفلية
            cleaned = re.sub(r'[^a-zA-Z0-9_\u0600-\u06FF]', '', input_data)
            result["cleaned_data"] = cleaned[:50]  # الحد الأقصى 50 حرف
            
        elif input_type == "telegram_uid":
            # السماح فقط بالأرقام
            cleaned = re.sub(r'[^0-9]', '', input_data)
            result["cleaned_data"] = cleaned[:15]  # الحد الأقصى 15 رقم
            
        elif input_type == "general_text":
            # إزالة الرموز الخطيرة
            cleaned = re.sub(r'[<>"\'\;]', '', input_data)
            result["cleaned_data"] = cleaned[:1000]  # الحد الأقصى 1000 حرف
        
        # التحقق من الطول
        if len(input_data) > 10000:  # 10KB
            result["warnings"].append("البيانات طويلة جداً")
            result["blocked"] = True
        
        # إذا كان هناك محتوى مشبوه، تسجيله
        if result["blocked"]:
            result["valid"] = False
        
        return result
    
    def _log_security_event(self, event_type: str, identifier: str = None,
                           identifier_type: str = None, event_data: Dict = None,
                           severity: int = 1, source_ip: str = None):
        """تسجيل حدث أمني"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO security_log 
                    (event_type, identifier, identifier_type, event_data, severity, source_ip)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (event_type, identifier or '', identifier_type or '',
                      json.dumps(event_data) if event_data else '', 
                      severity, source_ip or ''))
                conn.commit()
                
        except Exception as e:
            print(f"خطأ في تسجيل الحدث الأمني: {e}")
    
    def get_security_report(self, days: int = 7) -> Dict[str, Any]:
        """الحصول على تقرير أمني شامل"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                since_date = datetime.now() - timedelta(days=days)
                
                # إحصائيات المحاولات الفاشلة
                cursor = conn.execute('''
                    SELECT COUNT(*), 
                           COUNT(DISTINCT identifier) as unique_identifiers,
                           AVG(severity) as avg_severity
                    FROM failed_attempts 
                    WHERE attempt_time >= ?
                ''', (since_date.isoformat(),))
                failed_stats = cursor.fetchone()
                
                # إحصائيات الحظر
                cursor = conn.execute('''
                    SELECT COUNT(*), 
                           COUNT(DISTINCT identifier) as unique_blocked,
                           AVG(block_level) as avg_block_level
                    FROM active_blocks 
                    WHERE created_at >= ?
                ''', (since_date.isoformat(),))
                block_stats = cursor.fetchone()
                
                # إحصائيات الأنشطة المشبوهة
                cursor = conn.execute('''
                    SELECT COUNT(*), 
                           COUNT(DISTINCT identifier) as unique_suspicious,
                           AVG(risk_score) as avg_risk,
                           SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved_count
                    FROM suspicious_activities 
                    WHERE detection_time >= ?
                ''', (since_date.isoformat(),))
                suspicious_stats = cursor.fetchone()
                
                # أهم الأحداث الأمنية
                cursor = conn.execute('''
                    SELECT event_type, COUNT(*) as count
                    FROM security_log 
                    WHERE timestamp >= ? 
                    GROUP BY event_type 
                    ORDER BY count DESC 
                    LIMIT 10
                ''', (since_date.isoformat(),))
                top_events = cursor.fetchall()
                
                return {
                    "period_days": days,
                    "failed_attempts": {
                        "total": failed_stats[0] or 0,
                        "unique_identifiers": failed_stats[1] or 0,
                        "average_severity": round(failed_stats[2] or 0, 2)
                    },
                    "blocks": {
                        "total": block_stats[0] or 0,
                        "unique_blocked": block_stats[1] or 0,
                        "average_level": round(block_stats[2] or 0, 2)
                    },
                    "suspicious_activities": {
                        "total": suspicious_stats[0] or 0,
                        "unique_identifiers": suspicious_stats[1] or 0,
                        "average_risk": round(suspicious_stats[2] or 0, 2),
                        "resolved": suspicious_stats[3] or 0
                    },
                    "top_security_events": [
                        {"event_type": event, "count": count} 
                        for event, count in top_events
                    ]
                }
                
        except Exception as e:
            print(f"خطأ في إنشاء التقرير الأمني: {e}")
            return {"error": str(e)}
    
    def cleanup_old_records(self, days_to_keep: int = 90) -> Dict[str, int]:
        """تنظيف السجلات القديمة"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            with sqlite3.connect(self.db_path) as conn:
                # تنظيف المحاولات الفاشلة القديمة
                cursor = conn.execute(
                    'DELETE FROM failed_attempts WHERE attempt_time < ?',
                    (cutoff_date.isoformat(),)
                )
                failed_deleted = cursor.rowcount
                
                # تنظيف سجل الأحداث القديم
                cursor = conn.execute(
                    'DELETE FROM security_log WHERE timestamp < ?',
                    (cutoff_date.isoformat(),)
                )
                log_deleted = cursor.rowcount
                
                # تنظيف حدود المعدل القديمة
                cursor = conn.execute(
                    'DELETE FROM rate_limits WHERE window_start < ?',
                    (cutoff_date.isoformat(),)
                )
                rate_deleted = cursor.rowcount
                
                # تنظيف الأنشطة المشبوهة المحلولة القديمة
                cursor = conn.execute('''
                    DELETE FROM suspicious_activities 
                    WHERE resolved = 1 AND detection_time < ?
                ''', (cutoff_date.isoformat(),))
                suspicious_deleted = cursor.rowcount
                
                conn.commit()
                
                return {
                    "failed_attempts_deleted": failed_deleted,
                    "security_log_deleted": log_deleted,
                    "rate_limits_deleted": rate_deleted,
                    "suspicious_activities_deleted": suspicious_deleted
                }
                
        except Exception as e:
            print(f"خطأ في تنظيف السجلات القديمة: {e}")
            return {"error": str(e)}


def main():
    """
    دالة اختبار أساسية لأدوات الأمان
    """
    print("اختبار أدوات الأمان...")
    
    # إنشاء مثيل من أدوات الأمان
    security_utils = SecurityUtils()
    
    # اختبار تسجيل محاولة فاشلة
    user_id = "test_user_001"
    print(f"تسجيل محاولة فاشلة للمستخدم: {user_id}")
    
    attempt_result = security_utils.record_failed_attempt(
        user_id, "user", "login", "192.168.1.100", 
        "Mozilla/5.0 Test Browser", "كلمة مرور خاطئة", 2
    )
    print(f"نتيجة تسجيل المحاولة: {attempt_result}")
    
    # اختبار التحقق من حالة الحظر
    block_status = security_utils.check_block_status(user_id, "user")
    print(f"حالة الحظر: {block_status}")
    
    # اختبار حدود المعدل
    rate_limit = security_utils.check_rate_limit("192.168.1.100", "ip")
    print(f"حدود المعدل: {rate_limit}")
    
    # اختبار قوة كلمة المرور
    password_strength = security_utils.validate_password_strength(
        "MyStr0ngP@ssw0rd!", "testuser"
    )
    print(f"قوة كلمة المرور: {password_strength}")
    
    # اختبار تشفير كلمة المرور
    password = "MySecretPassword123!"
    hashed = security_utils.hash_password(password)
    print(f"كلمة المرور مشفرة: {hashed[:50]}...")
    
    # اختبار التحقق من كلمة المرور
    is_valid = security_utils.verify_password(password, hashed)
    print(f"التحقق من كلمة المرور: {is_valid}")
    
    # اختبار التحقق من المدخلات
    input_validation = security_utils.validate_input(
        "اسم المستخدم العادي", "username"
    )
    print(f"التحقق من المدخلات: {input_validation}")
    
    # اختبار نشاط مشبوه
    security_utils.record_suspicious_activity(
        user_id, "user", "multiple_failed_logins", 3,
        "محاولات دخول متعددة فاشلة في فترة قصيرة"
    )
    
    # الحصول على التقرير الأمني
    security_report = security_utils.get_security_report(7)
    print(f"التقرير الأمني: {security_report}")
    
    print("انتهى الاختبار.")


if __name__ == "__main__":
    main()