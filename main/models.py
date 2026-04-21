from django.db import models
from django.utils import timezone


class ScanResult(models.Model):
    SCAN_TYPE_CHOICES = [
        ('url', 'URL / Ссылка'),
        ('apk', 'APK Файл'),
        ('qr', 'QR Code'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Ожидание'),
        ('scanning', 'Сканирование'),
        ('done', 'Завершено'),
        ('error', 'Ошибка'),
    ]

    # Основные поля
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    # Для URL сканирования
    url = models.URLField(max_length=2048, null=True, blank=True)

    # Для APK сканирования
    file = models.FileField(upload_to='apk_uploads/', null=True, blank=True)
    file_name = models.CharField(max_length=255, null=True, blank=True)
    file_size = models.PositiveBigIntegerField(null=True, blank=True)  # байты
    file_hash_sha256 = models.CharField(max_length=64, null=True, blank=True)

    # VirusTotal результаты
    vt_scan_id = models.CharField(max_length=255, null=True, blank=True)  # ID анализа в VT
    vt_permalink = models.URLField(max_length=512, null=True, blank=True)  # Ссылка на отчёт VT
    malicious_count = models.IntegerField(default=0)    # сколько движков нашли угрозу
    suspicious_count = models.IntegerField(default=0)   # подозрительно
    harmless_count = models.IntegerField(default=0)     # чистых
    undetected_count = models.IntegerField(default=0)   # не проверили
    total_engines = models.IntegerField(default=0)      # всего движков

    # Итоговый вердикт
    is_phishing = models.BooleanField(null=True, blank=True)  # True = опасно
    threat_label = models.CharField(max_length=255, null=True, blank=True)  # напр. "phishing/malware"

    # Полный JSON ответ от VirusTotal (для деталей)
    raw_result = models.JSONField(null=True, blank=True)

    # IP пользователя (опционально для логов)
    user_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Результат сканирования'
        verbose_name_plural = 'Результаты сканирований'

    def __str__(self):
        target = self.url if self.scan_type == 'url' else self.file_name
        return f"[{self.scan_type.upper()}] {target} — {self.status}"

    @property
    def danger_percent(self):
        """Процент опасности: сколько движков считают угрозой"""
        if self.total_engines == 0:
            return 0
        return round((self.malicious_count / self.total_engines) * 100, 1)

    @property
    def verdict(self):
        """Читаемый вердикт"""
        if self.malicious_count >= 5:
            return 'dangerous'
        elif self.malicious_count >= 1 or self.suspicious_count >= 3:
            return 'suspicious'
        else:
            return 'clean'