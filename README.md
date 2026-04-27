# MultiAvScanner

**Многоантивирусный онлайн-сканер файлов с интеграцией искусственного интеллекта Google Gemini**

Современный аналог VirusTotal, который объединяет несколько антивирусных движков и мощный ИИ-анализ для глубокого и понятного исследования подозрительных файлов.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)
![React](https://img.shields.io/badge/React-18+-61DAFB.svg)
![Docker](https://img.shields.io/badge/Docker-2496ED.svg)

## ✨ Основные возможности

- Одновременное сканирование файла **несколькими антивирусными движками**
- Интеграция **Google Gemini** (1.5 Flash / Pro) для интеллектуального анализа
- Понятные человеческие отчёты с объяснением поведения вредоноса
- Асинхронная обработка задач через Celery + RabbitMQ
- Поддержка WebSocket — отслеживание прогресса в реальном времени
- Удобный современный веб-интерфейс (React + TypeScript)
- REST API с подробной документацией (Swagger)
- Высокий уровень безопасности и защиты от злоупотреблений
- Экспорт отчётов в PDF и JSON

## 🛠 Технологический стек

**Backend:**
- Python 3.11+
- FastAPI
- Celery + RabbitMQ
- PostgreSQL
- MinIO (S3-совместимое хранилище)
- Docker + Docker Compose

**Frontend:**
- React 18 + TypeScript
- Material-UI
- Socket.IO (WebSocket)

**Анализ:**
- ClamAV
- YARA
- VirusTotal API (опционально)
- Google Gemini API

## 🚀 Быстрый запуск (для разработки)

```bash
# Клонирование репозитория
git clone https://github.com/xshohjahon/MultiAvScanner.git
cd MultiAvScanner

# Запуск через Docker Compose
docker compose up --build
