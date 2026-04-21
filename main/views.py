import hashlib
import os
import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.utils import timezone
from django.conf import settings
from .models import ScanResult
import time
from .utils import decode_qr, check_pwned_password

VT_API_KEY = settings.VIRUSTOTAL_API_KEY
VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}


# ────────────────────────────────────────────
#  Главная страница
# ────────────────────────────────────────────
class HomeView(View):
    def get(self, request):
        recent = ScanResult.objects.filter(status='done').order_by('-created_at')[:10]
        return render(request, 'main/index.html', {'recent': recent})


# ────────────────────────────────────────────
#  Сканирование URL
# ────────────────────────────────────────────
class ScanURLView(View):
    def post(self, request):
        url = request.POST.get('url', '').strip()
        if not url:
            return JsonResponse({'error': 'URL не указан'}, status=400)

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        existing = ScanResult.objects.filter(
            url=url,
            status='done'
        ).order_by('-created_at').first()

        if existing:
            return JsonResponse(build_response(existing))


        # Создаём запись в БД
        scan = ScanResult.objects.create(
            scan_type='url',
            url=url,
            status='scanning',
            user_ip=get_client_ip(request),
        )

        try:
            # Шаг 1: Отправляем URL на VirusTotal
            response = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=HEADERS,
                data={"url": url},
                timeout=15,
            )
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]

            # Шаг 2: Ждём результат (polling)
            result_data = wait_for_analysis(analysis_id)

            if result_data is None:
                scan.status = 'error'
                scan.save()
                return JsonResponse({'error': 'Таймаут анализа VirusTotal'}, status=504)

            # Шаг 3: Сохраняем результат
            stats = result_data["data"]["attributes"]["stats"]
            scan = save_scan_result(scan, analysis_id, stats, result_data)

            return JsonResponse(build_response(scan))

        except requests.RequestException as e:
            scan.status = 'error'
            scan.save()
            return JsonResponse({'error': f'Ошибка запроса: {str(e)}'}, status=500)


# ────────────────────────────────────────────
#  Сканирование APK файла
# ────────────────────────────────────────────
class ScanFileView(View):
    MAX_SIZE = 32 * 1024 * 1024  # 32 MB

    def post(self, request):
        uploaded = request.FILES.get('file')

        if not uploaded:
            return JsonResponse({'error': 'Файл не загружен'}, status=400)

        if not uploaded.name.endswith('.apk'):
            return JsonResponse({'error': 'Разрешены только .apk файлы'}, status=400)

        if uploaded.size > self.MAX_SIZE:
            return JsonResponse({'error': 'Файл слишком большой (макс. 32MB)'}, status=400)

        # Считаем SHA256 хеш файла
        file_bytes = uploaded.read()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        uploaded.seek(0)

        existing = ScanResult.objects.filter(
            file_hash_sha256=sha256,
            status='done'
        ).order_by('-created_at').first()

        if existing:
            return JsonResponse(build_response(existing))

        # Создаём запись в БД
        scan = ScanResult.objects.create(
            scan_type='apk',
            file=uploaded,
            file_name=uploaded.name,
            file_size=uploaded.size,
            file_hash_sha256=sha256,
            status='scanning',
            user_ip=get_client_ip(request),
        )

        try:
            # Шаг 1: Сначала проверяем по хешу (быстрее)
            hash_result = check_by_hash(sha256)

            if hash_result:
                stats = hash_result["data"]["attributes"]["last_analysis_stats"]
                scan = save_scan_result(scan, sha256, stats, hash_result)
                return JsonResponse(build_response(scan))

            # Шаг 2: Хеш не найден — загружаем файл
            upload_response = requests.post(
                f"{VT_BASE_URL}/files",
                headers=HEADERS,
                files={"file": (uploaded.name, file_bytes, "application/octet-stream")},
                timeout=60,
            )
            upload_response.raise_for_status()
            analysis_id = upload_response.json()["data"]["id"]

            # Шаг 3: Ждём результат
            result_data = wait_for_analysis(analysis_id)

            if result_data is None:
                scan.status = 'error'
                scan.save()
                return JsonResponse({'error': 'Таймаут анализа VirusTotal'}, status=504)

            stats = result_data["data"]["attributes"]["stats"]
            scan = save_scan_result(scan, analysis_id, stats, result_data)

            return JsonResponse(build_response(scan))

        except requests.RequestException as e:
            scan.status = 'error'
            scan.save()
            return JsonResponse({'error': f'Ошибка запроса: {str(e)}'}, status=500)


# ────────────────────────────────────────────
#  История сканирований
# ────────────────────────────────────────────
class HistoryView(View):
    def get(self, request):
        scans = ScanResult.objects.filter(status='done').order_by('-created_at')[:50]
        return render(request, 'main/history.html', {'scans': scans})


# ────────────────────────────────────────────
#  Детали одного скана (AJAX)
# ────────────────────────────────────────────
class ScanDetailView(View):
    def get(self, request, scan_id):
        try:
            scan = ScanResult.objects.get(id=scan_id)
        except ScanResult.DoesNotExist:
            return JsonResponse({'error': 'Не найдено'}, status=404)

        return JsonResponse(build_response(scan))


# ════════════════════════════════════════════
#  Вспомогательные функции
# ════════════════════════════════════════════

def wait_for_analysis(analysis_id, max_attempts=10, delay=3):
    """Polling: ждём пока VirusTotal завершит анализ"""
    for _ in range(max_attempts):
        time.sleep(delay)
        resp = requests.get(
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data["data"]["attributes"]["status"] == "completed":
                return data
    return None


def check_by_hash(sha256):
    """Проверяем файл по SHA256 хешу — быстрее чем загружать"""
    resp = requests.get(
        f"{VT_BASE_URL}/files/{sha256}",
        headers=HEADERS,
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def save_scan_result(scan, analysis_id, stats, raw_data):
    """Сохраняем результат в БД"""
    scan.vt_scan_id = analysis_id
    scan.malicious_count = stats.get('malicious', 0)
    scan.suspicious_count = stats.get('suspicious', 0)
    scan.harmless_count = stats.get('harmless', 0)
    scan.undetected_count = stats.get('undetected', 0)
    scan.total_engines = sum(stats.values())
    scan.is_phishing = scan.malicious_count >= 3
    scan.raw_result = raw_data
    scan.status = 'done'
    scan.finished_at = timezone.now()
    scan.save()
    return scan


def build_response(scan):
    """Формируем JSON ответ для фронтенда"""
    return {
        'id': scan.id,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'verdict': scan.verdict,
        'danger_percent': scan.danger_percent,
        'malicious': scan.malicious_count,
        'suspicious': scan.suspicious_count,
        'harmless': scan.harmless_count,
        'undetected': scan.undetected_count,
        'total_engines': scan.total_engines,
        'is_phishing': scan.is_phishing,
        'url': scan.url,
        'file_name': scan.file_name,
        'file_hash': scan.file_hash_sha256,
        'created_at': scan.created_at.strftime('%d.%m.%Y %H:%M'),
    }


def get_client_ip(request):
    """Получаем IP пользователя"""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


class ScanQRView(View):
    def post(self, request):
        file = request.FILES.get('qr')

        if not file:
            return JsonResponse({'error': 'Файл не загружен'}, status=400)

        if not file.content_type.startswith('image/'):
            return JsonResponse({'error': 'Нужен файл изображения'}, status=400)

        scan = ScanResult.objects.create(
            scan_type='qr',
            status='scanning',
            user_ip=get_client_ip(request),
        )

        try:
            os.makedirs('media', exist_ok=True)
            path = os.path.join('media', file.name)
            with open(path, 'wb+') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            result = decode_qr(path)

            if not result:
                scan.status = 'error'
                scan.save()
                return JsonResponse({'error': 'QR не распознан'}, status=400)

            # сохраним содержимое QR как url, если это ссылка
            if result.startswith(('http://', 'https://')):
                scan.url = result

                response = requests.post(
                    f"{VT_BASE_URL}/urls",
                    headers=HEADERS,
                    data={"url": result},
                    timeout=15,
                )
                response.raise_for_status()
                analysis_id = response.json()["data"]["id"]

                result_data = wait_for_analysis(analysis_id)

                if result_data is None:
                    scan.status = 'error'
                    scan.save()
                    return JsonResponse({'error': 'Таймаут анализа VirusTotal'}, status=504)

                stats = result_data["data"]["attributes"]["stats"]
                scan = save_scan_result(scan, analysis_id, stats, result_data)

                data = build_response(scan)
                data['decoded'] = result
                return JsonResponse(data)

            # если QR не ссылка, просто сохраняем как успешно распознанный
            scan.status = 'done'
            scan.raw_result = {'decoded': result}
            scan.finished_at = timezone.now()
            scan.save()

            return JsonResponse({
                'id': scan.id,
                'scan_type': 'qr',
                'status': 'done',
                'decoded': result,
                'message': 'QR код распознан, но это не ссылка',
            })

        except requests.RequestException as e:
            scan.status = 'error'
            scan.save()
            return JsonResponse({'error': f'Ошибка запроса: {str(e)}'}, status=500)

        except Exception as e:
            scan.status = 'error'
            scan.save()
            return JsonResponse({'error': str(e)}, status=500)

class ScanPasswordView(View):
    def post(self, request):
        password = request.POST.get('password', '').strip()

        if not password:
            return JsonResponse({'error': 'Пароль не указан'}, status=400)

        try:
            result = check_pwned_password(password)

            if result['pwned']:
                verdict = 'dangerous'
                title = 'Этот пароль небезопасен'
                message = f"Пароль найден в утечках {result['count']} раз"

                recommendation = (
                    "Этот пароль уже использовался в утечках данных и считается небезопасным. "
                    "Рекомендуем срочно изменить его.\n"
                    "Используйте длинный пароль (12–16+ символов), добавьте заглавные буквы, цифры и специальные символы.\n"
                    "Нажмите кнопку ниже, чтобы сгенерировать надёжный пароль."
                )

            else:
                verdict = 'clean'
                title = 'Пароль не найден в утечках'
                message = 'Пароль не найден в известных базах утечек.'

                recommendation = (
                    "Это хороший знак, но не гарантия полной безопасности.\n"
                    "Рекомендуется использовать уникальный пароль длиной не менее 12–16 символов, "
                    "с буквами, цифрами и специальными символами.\n"
                    "Вы можете сгенерировать более надёжный пароль ниже."
                )
            return JsonResponse({
                'status': 'done',
                'scan_type': 'password',
                'verdict': verdict,
                'title': title,
                'message': message,
                'recommendation': recommendation,
                'pwned': result['pwned'],
                'count': result['count'],
                'danger_percent': 100 if result['pwned'] else 15,
                'malicious': 1 if result['pwned'] else 0,
                'suspicious': 0,
                'harmless': 1 if not result['pwned'] else 0,
                'undetected': 0,
                'total_engines': 1,
                'decoded': password[:2] + '*' * max(len(password) - 2, 0)
            })

        except requests.RequestException as e:
            return JsonResponse({'error': f'Ошибка запроса: {str(e)}'}, status=500)