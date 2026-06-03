import hashlib
import logging
import os
import tempfile
import time
from datetime import timedelta

import requests
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views import View

from .models import ScanResult, ScreenshotScan
from .utils import decode_qr, check_pwned_password
from .ai_screenshot import analyze_screenshot_with_gemini

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════
#  Кастомные исключения
# ════════════════════════════════════════════

class VTRateLimitError(Exception):
    """VirusTotal вернул 429 — превышен лимит запросов."""

class VTTimeoutError(Exception):
    """Анализ не завершился за отведённое время."""


# ════════════════════════════════════════════
#  VirusTotal клиент — вся работа с API здесь
# ════════════════════════════════════════════

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    POLL_DELAY = 2          # секунды между попытками
    POLL_MAX_ATTEMPTS = 25  # максимум ~50 секунд

    # Retry при 429: сколько раз пробовать и сколько ждать между попытками
    RATE_LIMIT_RETRIES = 3
    RATE_LIMIT_DELAY = 20   # секунд (бесплатный план — 4 req/min)

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": settings.VIRUSTOTAL_API_KEY})

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Обёртка над session.request с автоматическим retry при 429.
        Бросает VTRateLimitError если все попытки исчерпаны.
        """
        for attempt in range(1, self.RATE_LIMIT_RETRIES + 1):
            resp = self.session.request(method, url, **kwargs)

            if resp.status_code != 429:
                resp.raise_for_status()
                return resp

            # Берём Retry-After из заголовков если есть, иначе наш дефолт
            retry_after = int(resp.headers.get("Retry-After", self.RATE_LIMIT_DELAY))
            logger.warning(
                "VT rate limit hit (attempt %d/%d), waiting %ds...",
                attempt, self.RATE_LIMIT_RETRIES, retry_after,
            )

            if attempt < self.RATE_LIMIT_RETRIES:
                time.sleep(retry_after)

        raise VTRateLimitError(
            "Превышен лимит запросов VirusTotal. "
            "Бесплатный план позволяет 4 запроса в минуту — попробуйте через минуту."
        )

    def submit_url(self, url: str) -> str:
        """Отправляет URL на анализ, возвращает analysis_id."""
        resp = self._request(
            "POST",
            f"{self.BASE_URL}/urls",
            data={"url": url},
            timeout=15,
        )
        return resp.json()["data"]["id"]

    def submit_file(self, filename: str, file_bytes: bytes) -> str:
        """Загружает файл на анализ, возвращает analysis_id."""
        resp = self._request(
            "POST",
            f"{self.BASE_URL}/files",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=60,
        )
        return resp.json()["data"]["id"]

    def get_by_hash(self, sha256: str) -> dict | None:
        """Проверяет файл по SHA256. Возвращает данные или None если не найден."""
        resp = self.session.get(
            f"{self.BASE_URL}/files/{sha256}",
            timeout=10,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise VTRateLimitError(
                "Превышен лимит запросов VirusTotal — попробуйте через минуту."
            )
        resp.raise_for_status()
        return resp.json()

    def wait_for_analysis(self, analysis_id: str) -> dict | None:
        """
        Polling: ждёт завершения анализа.
        Возвращает данные или None при таймауте.
        """
        for attempt in range(self.POLL_MAX_ATTEMPTS):
            time.sleep(self.POLL_DELAY)
            try:
                resp = self.session.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data["data"]["attributes"]["status"] == "completed":
                        return data
                # При 429 во время polling — просто ждём дольше
                elif resp.status_code == 429:
                    logger.warning("VT rate limit during polling, sleeping 20s")
                    time.sleep(20)
            except requests.RequestException:
                logger.warning(
                    "VT polling attempt %d/%d failed for %s",
                    attempt + 1, self.POLL_MAX_ATTEMPTS, analysis_id,
                )
        return None


# ════════════════════════════════════════════
#  Сервисный слой — бизнес-логика
# ════════════════════════════════════════════

CACHE_TTL_HOURS = 24  # сколько часов считать кэш актуальным

class ScanService:
    def __init__(self):
        self.vt = VirusTotalClient()

    # ─── Общие утилиты ───────────────────────

    def _get_cached_scan(self, **filters) -> ScanResult | None:
        """Ищет свежий завершённый скан по фильтрам."""
        cutoff = timezone.now() - timedelta(hours=CACHE_TTL_HOURS)
        return (
            ScanResult.objects
            .filter(status="done", created_at__gte=cutoff, **filters)
            .order_by("-created_at")
            .first()
        )

    def _save_vt_result(
        self,
        scan: ScanResult,
        analysis_id: str,
        stats: dict,
        raw_data: dict,
    ) -> ScanResult:
        """Записывает результат VirusTotal в модель."""
        scan.vt_scan_id = analysis_id
        scan.malicious_count = stats.get("malicious", 0)
        scan.suspicious_count = stats.get("suspicious", 0)
        scan.harmless_count = stats.get("harmless", 0)
        scan.undetected_count = stats.get("undetected", 0)
        scan.total_engines = sum(stats.values())
        scan.is_phishing = scan.malicious_count >= 3
        scan.raw_result = raw_data
        scan.status = "done"
        scan.finished_at = timezone.now()
        scan.save()
        return scan

    def _fail_scan(self, scan: ScanResult, reason: str = "") -> None:
        scan.status = "error"
        if reason:
            scan.raw_result = {"error": reason}
        scan.save()

    def _poll_or_fail(
        self,
        scan: ScanResult,
        analysis_id: str,
    ) -> dict | None:
        """
        Ждёт результат от VT. При таймауте помечает скан как ошибку
        и возвращает None.
        """
        result = self.vt.wait_for_analysis(analysis_id)
        if result is None:
            self._fail_scan(scan, "VirusTotal analysis timeout")
        return result

    # ─── URL ─────────────────────────────────

    def scan_url(self, url: str, user_ip: str) -> ScanResult:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        cached = self._get_cached_scan(url=url, scan_type="url")
        if cached:
            return cached

        scan = ScanResult.objects.create(
            scan_type="url",
            url=url,
            status="scanning",
            user_ip=user_ip,
        )

        analysis_id = self.vt.submit_url(url)

        result = self._poll_or_fail(scan, analysis_id)
        if result is None:
            return scan

        stats = result["data"]["attributes"]["stats"]
        return self._save_vt_result(scan, analysis_id, stats, result)

    # ─── APK ─────────────────────────────────

    def scan_apk(self, filename: str, file_bytes: bytes, user_ip: str) -> ScanResult:
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        cached = self._get_cached_scan(file_hash_sha256=sha256)
        if cached:
            return cached

        scan = ScanResult.objects.create(
            scan_type="apk",
            file_name=filename,
            file_size=len(file_bytes),
            file_hash_sha256=sha256,
            status="scanning",
            user_ip=user_ip,
        )

        # Сначала проверяем по хешу — быстрее чем загружать файл
        hash_result = self.vt.get_by_hash(sha256)
        if hash_result:
            stats = hash_result["data"]["attributes"]["last_analysis_stats"]
            return self._save_vt_result(scan, sha256, stats, hash_result)

        # Хеш не найден — загружаем файл
        analysis_id = self.vt.submit_file(filename, file_bytes)

        result = self._poll_or_fail(scan, analysis_id)
        if result is None:
            return scan

        stats = result["data"]["attributes"]["stats"]
        return self._save_vt_result(scan, analysis_id, stats, result)

    # ─── QR ──────────────────────────────────

    def scan_qr(self, file, user_ip: str) -> tuple[ScanResult | None, str | None]:
        """
        Возвращает (scan, decoded_text).
        scan может быть None если QR не распознан.
        """
        scan = ScanResult.objects.create(
            scan_type="qr",
            status="scanning",
            user_ip=user_ip,
        )

        # Сохраняем во временный файл, который удалится автоматически
        suffix = os.path.splitext(file.name)[1] or ".png"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            for chunk in file.chunks():
                tmp.write(chunk)
            tmp.flush()
            decoded = decode_qr(tmp.name)

        if not decoded:
            self._fail_scan(scan, "QR not recognized")
            return None, None

        # Если QR содержит URL — сканируем его
        if decoded.startswith(("http://", "https://")):
            scan.url = decoded
            scan.save(update_fields=["url"])

            analysis_id = self.vt.submit_url(decoded)
            result = self._poll_or_fail(scan, analysis_id)
            if result is None:
                return scan, decoded

            stats = result["data"]["attributes"]["stats"]
            return self._save_vt_result(scan, analysis_id, stats, result), decoded

        # QR не ссылка — просто сохраняем
        scan.status = "done"
        scan.raw_result = {"decoded": decoded}
        scan.finished_at = timezone.now()
        scan.save()
        return scan, decoded


# ════════════════════════════════════════════
#  Вспомогательные функции
# ════════════════════════════════════════════

def get_client_ip(request) -> str:
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def get_file_sha256(uploaded_file) -> str:
    hasher = hashlib.sha256()
    for chunk in uploaded_file.chunks():
        hasher.update(chunk)
    uploaded_file.seek(0)
    return hasher.hexdigest()


def build_response(scan: ScanResult) -> dict:
    """Сериализует ScanResult в JSON-ответ для фронтенда."""
    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "verdict": getattr(scan, "verdict", None),
        "danger_percent": getattr(scan, "danger_percent", 0),
        "malicious": scan.malicious_count,
        "suspicious": scan.suspicious_count,
        "harmless": scan.harmless_count,
        "undetected": scan.undetected_count,
        "total_engines": scan.total_engines,
        "is_phishing": scan.is_phishing,
        "url": scan.url,
        "file_name": scan.file_name,
        "file_hash": scan.file_hash_sha256,
        "created_at": scan.created_at.strftime("%d.%m.%Y %H:%M"),
    }


def error_response(message: str, status: int = 400) -> JsonResponse:
    return JsonResponse({"error": message}, status=status)


# ════════════════════════════════════════════
#  Views — только HTTP-логика
# ════════════════════════════════════════════

class HomeView(View):
    def get(self, request):
        recent = ScanResult.objects.filter(status="done").order_by("-created_at")[:10]
        return render(request, "main/index.html", {"recent": recent})


class HistoryView(View):
    def get(self, request):
        scans = ScanResult.objects.filter(status="done").order_by("-created_at")[:50]
        return render(request, "main/history.html", {"scans": scans})


class ScanDetailView(View):
    def get(self, request, scan_id):
        try:
            scan = ScanResult.objects.get(id=scan_id)
        except ScanResult.DoesNotExist:
            return error_response("Не найдено", status=404)
        return JsonResponse(build_response(scan))


class ScanURLView(View):
    def post(self, request):
        url = request.POST.get("url", "").strip()
        if not url:
            return error_response("URL не указан")

        try:
            service = ScanService()
            scan = service.scan_url(url, user_ip=get_client_ip(request))
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException as e:
            logger.exception("VT request failed for URL: %s", url)
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        return JsonResponse(build_response(scan))


class ScanFileView(View):
    MAX_SIZE = 32 * 1024 * 1024  # 32 MB

    def post(self, request):
        uploaded = request.FILES.get("file")

        if not uploaded:
            return error_response("Файл не загружен")
        if not uploaded.name.endswith(".apk"):
            return error_response("Разрешены только .apk файлы")
        if uploaded.size > self.MAX_SIZE:
            return error_response("Файл слишком большой (макс. 32MB)")

        file_bytes = uploaded.read()

        try:
            service = ScanService()
            scan = service.scan_apk(
                filename=uploaded.name,
                file_bytes=file_bytes,
                user_ip=get_client_ip(request),
            )
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException as e:
            logger.exception("VT request failed for APK: %s", uploaded.name)
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        return JsonResponse(build_response(scan))


class ScanQRView(View):
    def post(self, request):
        file = request.FILES.get("qr")

        if not file:
            return error_response("Файл не загружен")
        if not file.content_type.startswith("image/"):
            return error_response("Нужен файл изображения")

        try:
            service = ScanService()
            scan, decoded = service.scan_qr(file, user_ip=get_client_ip(request))
        except VTRateLimitError as e:
            return error_response(str(e), status=429)
        except requests.RequestException as e:
            logger.exception("VT request failed for QR")
            return error_response("Не удалось связаться с VirusTotal. Попробуйте позже.", status=502)
        except Exception as e:
            logger.exception("QR scan failed")
            return error_response(str(e), status=500)

        if scan is None:
            return error_response("QR не распознан")

        if scan.status == "error":
            return error_response("Анализ занял слишком долго. Попробуйте ещё раз.", status=504)

        # QR не ссылка
        if scan.raw_result and "decoded" in scan.raw_result and not scan.url:
            return JsonResponse({
                "id": scan.id,
                "scan_type": "qr",
                "status": "done",
                "decoded": decoded,
                "message": "QR код распознан, но это не ссылка",
            })

        data = build_response(scan)
        data["decoded"] = decoded
        return JsonResponse(data)


class ScanPasswordView(View):
    def post(self, request):
        password = request.POST.get("password", "").strip()
        if not password:
            return error_response("Пароль не указан")

        try:
            result = check_pwned_password(password)
        except requests.RequestException as e:
            logger.exception("HIBP request failed")
            return error_response(f"Ошибка запроса: {e}", status=500)

        pwned = result["pwned"]
        count = result["count"]

        if pwned:
            verdict = "dangerous"
            title = "Этот пароль небезопасен"
            message = f"Пароль найден в утечках {count} раз"
            recommendation = (
                "Этот пароль уже использовался в утечках данных и считается небезопасным. "
                "Рекомендуем срочно изменить его.\n"
                "Используйте длинный пароль (12–16+ символов), добавьте заглавные буквы, "
                "цифры и специальные символы.\n"
                "Нажмите кнопку ниже, чтобы сгенерировать надёжный пароль."
            )
        else:
            verdict = "clean"
            title = "Пароль не найден в утечках"
            message = "Пароль не найден в известных базах утечек."
            recommendation = (
                "Это хороший знак, но не гарантия полной безопасности.\n"
                "Рекомендуется использовать уникальный пароль длиной не менее 12–16 символов, "
                "с буквами, цифрами и специальными символами.\n"
                "Вы можете сгенерировать более надёжный пароль ниже."
            )

        masked = password[:2] + "*" * max(len(password) - 2, 0)

        return JsonResponse({
            "status": "done",
            "scan_type": "password",
            "verdict": verdict,
            "title": title,
            "message": message,
            "recommendation": recommendation,
            "pwned": pwned,
            "count": count,
            "danger_percent": 100 if pwned else 15,
            "malicious": 1 if pwned else 0,
            "suspicious": 0,
            "harmless": 0 if pwned else 1,
            "undetected": 0,
            "total_engines": 1,
            "decoded": masked,
        })


class ScanScreenshotView(View):
    def post(self, request):
        image = request.FILES.get("screenshot")

        if not image:
            return error_response("Скриншот не загружен")
        if not image.content_type or not image.content_type.startswith("image/"):
            return error_response("Нужен файл изображения")

        file_hash = get_file_sha256(image)

        cached = ScreenshotScan.objects.filter(file_hash=file_hash).first()
        if cached:
            return JsonResponse({**cached.result, "cached": True})

        suffix = os.path.splitext(image.name)[1] or ".png"
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
                for chunk in image.chunks():
                    tmp.write(chunk)
                tmp.flush()
                result = analyze_screenshot_with_gemini(tmp.name)
        except Exception as e:
            return self._handle_gemini_error(e)

        verdict = result.get("verdict", "suspicious")
        risk_score = result.get("risk_score", 50)

        response_data = {
            "status": "done",
            "scan_type": "screenshot",
            "verdict": verdict,
            "title": result.get("summary", "AI анализ скриншота"),
            "decoded": result.get("detected_brand", "unknown"),
            "recommendation": result.get("recommendation", ""),
            "risk_score": risk_score,
            "suspicious_indicators": result.get("suspicious_indicators", []),
            "is_official_likely": result.get("is_official_likely", False),
            "danger_percent": risk_score,
            "malicious": 1 if verdict == "dangerous" else 0,
            "suspicious": 1 if verdict == "suspicious" else 0,
            "harmless": 1 if verdict == "clean" else 0,
            "undetected": 0,
            "total_engines": 1,
            "cached": False,
        }

        ScreenshotScan.objects.create(file_hash=file_hash, result=response_data)
        return JsonResponse(response_data)

    def _handle_gemini_error(self, exc: Exception) -> JsonResponse:
        err = str(exc)
        logger.exception("Gemini analysis failed")
        if "429" in err:
            return error_response("AI лимит исчерпан. Попробуйте позже или завтра.", status=429)
        if "503" in err or "UNAVAILABLE" in err:
            return error_response("AI сервис временно перегружен. Попробуйте через пару минут.", status=503)
        return error_response("Ошибка AI анализа", status=500)