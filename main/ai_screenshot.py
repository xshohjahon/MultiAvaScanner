import json
from PIL import Image
from google import genai
from django.conf import settings


def analyze_screenshot_with_gemini(image_path: str) -> dict:
    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    image = Image.open(image_path)

    prompt = """
Ты — помощник по кибербезопасности. Проанализируй скриншот уведомления, сообщения или сайта.

Задача:
1. Определи, похоже ли это на официальное уведомление или на фишинг/скам.
2. Обрати внимание на:
   - поддельное имя бренда;
   - подозрительные ссылки;
   - давление по времени;
   - просьбы подтвердить аккаунт;
   - угрозы блокировки;
   - домены, которые не похожи на официальный сайт;
   - ошибки в тексте;
   - подозрительные кнопки.
3. Не утверждай личность отправителя.
4. Верни только JSON без markdown.

Формат ответа:
{
  "verdict": "clean | suspicious | dangerous",
  "risk_score": 0,
  "is_official_likely": false,
  "summary": "краткий вывод",
  "detected_brand": "например Telegram или unknown",
  "suspicious_indicators": ["признак 1", "признак 2"],
  "recommendation": "что делать пользователю"
}
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=[prompt, image],
    )

    text = response.text.strip()

    if text.startswith("```"):
        text = text.replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(text)
    except Exception:
        return {
            "verdict": "suspicious",
            "risk_score": 50,
            "is_official_likely": False,
            "summary": text,
            "detected_brand": "unknown",
            "suspicious_indicators": [],
            "recommendation": "Проверьте ссылку вручную и не вводите личные данные."
        }