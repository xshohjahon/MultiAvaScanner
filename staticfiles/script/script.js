// ── Tabs ──
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn, .tab-panel').forEach(el => el.classList.remove('active'));
    btn.classList.add('active');

    const panel = document.getElementById('tab-' + btn.dataset.tab);
    if (panel) panel.classList.add('active');
  });
});

// ── Helper ──
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ── APK file select ──
const apkInput = document.getElementById('apk-input');
const dropZone = document.getElementById('drop-zone');
const fileSelected = document.getElementById('file-selected');
const btnApkScan = document.getElementById('btn-apk-scan');

function onFileChosen(file) {
  if (!file) return;

  document.getElementById('file-name-label').textContent = file.name;
  document.getElementById('file-size-label').textContent = formatSize(file.size);

  fileSelected.classList.add('show');
  btnApkScan.disabled = false;
}

if (apkInput) {
  apkInput.addEventListener('change', () => onFileChosen(apkInput.files[0]));
}

if (dropZone) {
  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');

    const file = e.dataTransfer.files[0];

    if (file && file.name.toLowerCase().endsWith('.apk')) {
      const dt = new DataTransfer();
      dt.items.add(file);
      apkInput.files = dt.files;
      onFileChosen(file);
    }
  });
}

// ── QR file select ──
const qrInput = document.getElementById('qr-input');
const qrDropZone = document.getElementById('qr-drop-zone');
const qrFileSelected = document.getElementById('qr-file-selected');
const btnQrScan = document.getElementById('btn-qr-scan');

function onQrChosen(file) {
  if (!file) return;

  document.getElementById('qr-file-name-label').textContent = file.name;
  document.getElementById('qr-file-size-label').textContent = formatSize(file.size);

  qrFileSelected.classList.add('show');
  btnQrScan.disabled = false;
}

if (qrInput) {
  qrInput.addEventListener('change', () => onQrChosen(qrInput.files[0]));
}

if (qrDropZone) {
  qrDropZone.addEventListener('dragover', e => {
    e.preventDefault();
    qrDropZone.classList.add('dragover');
  });

  qrDropZone.addEventListener('dragleave', () => {
    qrDropZone.classList.remove('dragover');
  });

  qrDropZone.addEventListener('drop', e => {
    e.preventDefault();
    qrDropZone.classList.remove('dragover');

    const file = e.dataTransfer.files[0];

    if (file && file.type.startsWith('image/')) {
      const dt = new DataTransfer();
      dt.items.add(file);
      qrInput.files = dt.files;
      onQrChosen(file);
    }
  });
}

// ── Show result ──
function showResult(prefix, data) {
  const verdict = data.verdict || 'suspicious';

  const icon =
    verdict === 'clean' ? '✅' :
    verdict === 'dangerous' ? '🚨' :
    '⚠️';

  const defaultTitle =
    verdict === 'clean' ? 'Безопасно' :
    verdict === 'dangerous' ? 'ОПАСНО!' :
    'Подозрительно';

  const title = data.title || defaultTitle;

  const color =
    verdict === 'clean' ? 'clean' :
    verdict === 'dangerous' ? 'danger' :
    'suspicious';

  const barColor =
    verdict === 'clean' ? 'green' :
    verdict === 'dangerous' ? 'red' :
    'yellow';

  const iconEl = document.getElementById(prefix + '-icon');
  const titleEl = document.getElementById(prefix + '-title');
  const subEl = document.getElementById(prefix + '-sub');

  if (iconEl) {
    iconEl.textContent = icon;
    iconEl.className = 'verdict-icon ' + color;
  }

  if (titleEl) {
    titleEl.textContent = title;
    titleEl.className = 'verdict-title ' + color;
  }

  // Password отдельный UI
  if (prefix === 'pw') {
    if (subEl) {
      subEl.innerHTML = data.pwned
        ? `Пароль найден в утечках: <b style="color:#ff4d4f">${data.count}</b> раз`
        : 'Пароль не найден в известных утечках';
    }

    const countEl = document.getElementById('pw-count');
    if (countEl) {
      countEl.textContent = data.pwned
        ? `Рекомендуется заменить пароль`
        : 'Это хороший знак, но используйте уникальный пароль';
    }

    const recEl = document.getElementById('pw-recommendation');
    if (recEl) {
      recEl.textContent = data.recommendation || '';
    }

    return;
  }

  // Screenshot AI отдельный UI
  if (prefix === 'sc') {
    if (subEl) {
      subEl.textContent = data.is_official_likely
        ? 'Похоже на официальное уведомление'
        : 'Вероятно фишинг / подделка';
    }

    const indicators = data.suspicious_indicators || [];
    const indicatorsEl = document.getElementById('sc-indicators');

    if (indicatorsEl) {
      indicatorsEl.textContent = indicators.length
        ? indicators.map(i => '• ' + i).join('\n')
        : 'Подозрительные признаки не найдены';
    }

    const recEl = document.getElementById('sc-recommendation');
    if (recEl) {
      recEl.textContent = data.recommendation || '';
    }
  } else {
    if (subEl) {
      subEl.textContent = data.decoded || data.url || data.file_name || '';
    }
  }

  // URL / APK / QR / Screenshot общая статистика
  const maliciousEl = document.getElementById(prefix + '-malicious');
  const suspiciousEl = document.getElementById(prefix + '-suspicious');
  const harmlessEl = document.getElementById(prefix + '-harmless');
  const undetectedEl = document.getElementById(prefix + '-undetected');
  const percentEl = document.getElementById(prefix + '-percent');
  const bar = document.getElementById(prefix + '-bar');

  if (maliciousEl) maliciousEl.textContent = data.malicious ?? 0;
  if (suspiciousEl) suspiciousEl.textContent = data.suspicious ?? 0;
  if (harmlessEl) harmlessEl.textContent = data.harmless ?? 0;
  if (undetectedEl) undetectedEl.textContent = data.undetected ?? 0;
  if (percentEl) percentEl.textContent = (data.danger_percent ?? data.risk_score ?? 0) + '%';

  if (bar) {
    const percent = data.danger_percent ?? data.risk_score ?? 0;
    bar.className = 'danger-bar-fill ' + barColor;
    setTimeout(() => {
      bar.style.width = percent + '%';
    }, 100);
  }
}

// ── AJAX submit ──
function submitForm(formId, loadingId, errorId, resultId, loadingTextId, prefix, loadingMessages) {
  const form = document.getElementById(formId);
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const loadingEl = document.getElementById(loadingId);
    const errorEl = document.getElementById(errorId);
    const resultEl = document.getElementById(resultId);
    const loadingTextEl = document.getElementById(loadingTextId);

    if (loadingEl) loadingEl.classList.add('show');
    if (errorEl) errorEl.classList.remove('show');
    if (resultEl) resultEl.classList.remove('show');

    let msgIndex = 0;

    const msgTimer = setInterval(() => {
      if (!loadingTextEl || !loadingMessages.length) return;
      msgIndex = (msgIndex + 1) % loadingMessages.length;
      loadingTextEl.textContent = loadingMessages[msgIndex];
    }, 3000);

    try {
      const formData = new FormData(form);

      const resp = await fetch(form.action, {
        method: 'POST',
        body: formData,
        headers: {
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      const data = await resp.json();

      clearInterval(msgTimer);
      if (loadingEl) loadingEl.classList.remove('show');

      if (data.error) {
        if (errorEl) {
          errorEl.textContent = '❌ ' + data.error;
          errorEl.classList.add('show');
        }
        return;
      }

      showResult(prefix, data);
      if (resultEl) resultEl.classList.add('show');

    } catch (err) {
      clearInterval(msgTimer);
      if (loadingEl) loadingEl.classList.remove('show');

      if (errorEl) {
        errorEl.textContent = '❌ Ошибка соединения: ' + err.message;
        errorEl.classList.add('show');
      }
    }
  });
}

// ── Password generator ──
function generateStrongPassword(length = 16) {
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}<>?';
  const all = lower + upper + numbers + symbols;

  let password = '';
  password += lower[Math.floor(Math.random() * lower.length)];
  password += upper[Math.floor(Math.random() * upper.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += symbols[Math.floor(Math.random() * symbols.length)];

  for (let i = 4; i < length; i++) {
    password += all[Math.floor(Math.random() * all.length)];
  }

  return password.split('').sort(() => Math.random() - 0.5).join('');
}

const generatePasswordBtn = document.getElementById('generate-password-btn');

if (generatePasswordBtn) {
  generatePasswordBtn.addEventListener('click', () => {
    const newPassword = generateStrongPassword(16);

    const generatedText = document.getElementById('generated-password-text');
    const generatedBox = document.getElementById('generated-password-box');
    const passwordInput = document.getElementById('password-input');

    if (generatedText) generatedText.textContent = newPassword;
    if (generatedBox) generatedBox.style.display = 'flex';
    if (passwordInput) passwordInput.value = newPassword;
  });
}


// ── Init forms ──
submitForm('form-url', 'loading-url', 'error-url', 'result-url', 'loading-text-url', 'r', [
  'Отправляем на VirusTotal...',
  'Ждём результаты от 70+ движков...',
  'Анализируем данные...',
  'Почти готово...'
]);

submitForm('form-apk', 'loading-apk', 'error-apk', 'result-apk', 'loading-text-apk', 'ra', [
  'Загружаем файл на VirusTotal...',
  'Проверяем по базе хешей...',
  'Запускаем антивирусные движки...',
  'Анализируем APK структуру...',
  'Почти готово...'
]);

submitForm('form-qr', 'loading-qr', 'error-qr', 'result-qr', 'loading-text-qr', 'qr', [
  'Распознаём QR код...',
  'Извлекаем содержимое...',
  'Проверяем ссылку через VirusTotal...',
  'Почти готово...'
]);

submitForm('form-password', 'loading-password', 'error-password', 'result-password', 'loading-text-password', 'pw', [
  'Считаем SHA-1...',
  'Отправляем префикс в HIBP...',
  'Сравниваем хеши...',
  'Почти готово...'
]);

submitForm('form-screenshot', 'loading-screenshot', 'error-screenshot', 'result-screenshot', 'loading-text-screenshot', 'sc', [
  'Анализируем изображение...',
  'Определяем бренд...',
  'Проверяем признаки фишинга...',
  'Формируем вывод...'
]);