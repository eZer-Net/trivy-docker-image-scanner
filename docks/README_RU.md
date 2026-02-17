# scan-dockers-trivy — надстройка над Trivy для скана Docker-образов и сборки отчёта

Этот репозиторий содержит Python-скрипт `trivy-scanner.py`, который **массово сканирует Docker-образы через Trivy** и сохраняет **компактный JSON-отчёт** с группировкой находок по типам компонентов и уровню критичности.

Сценарии:
- **Remote**: сканирование *удалённых* образов из registry (список в `input_images.txt`)
- **Local**: сборка образов из *локальных* `Dockerfile` и их сканирование (список в `input_images_files.txt`)
- **Both**: оба режима последовательно

---

## Что делает скрипт

### 1) Берёт цели из файлов ввода
- `input_images.txt` — список ссылок на образы (желательно с digest `@sha256:...`)
- `input_images_files.txt` — список путей к Dockerfile, которые нужно **собрать** и затем **просканировать**

В обоих файлах задаётся порог фильтрации по критичности: `severity=1..5`.

### 2) Готовит Trivy DB один раз и безопасно для параллельных запусков
Trivy не любит параллельные обновления DB в одном `--cache-dir`. Скрипт решает это так:
- создаёт локальный кэш `./.trivy_cache`
- **под файловой блокировкой** скачивает vulnerability DB (и при возможности Java DB) **один раз**
- дальше запускает сканы с `--skip-db-update` (и `--skip-java-db-update`, если Java DB доступна)

Если во время работы обнаруживается порча/недокачка БД — скрипт делает `repair` (удаляет `db/` и `java-db/` внутри кэша и скачивает заново) и повторяет скан 1 раз.

> ⚠️ Файловая блокировка реализована через `fcntl` и полноценно работает на Linux. На Windows межпроцессная защита может отсутствовать.

### 3) Сканирует параллельно и печатает прогресс
- Прогресс и сводки выводятся в **stderr**
- В **stdout** печатается **только имя итогового JSON-файла** (удобно для пайплайнов/скриптов)

### 4) Формирует итоговый JSON-отчёт
Результат сохраняется рядом со скриптом:
- `advanced_scan_results_remote_YYYYmmdd_HHMMSS.json`
- `advanced_scan_results_local_YYYYmmdd_HHMMSS.json`
- `advanced_scan_results_both_YYYYmmdd_HHMMSS.json`

---

## Требования

Минимально:
- **Python 3.8+** (зависимостей нет — только стандартная библиотека)
- **Trivy** в `PATH` (`trivy version` должен отрабатываться)
- Для режима **local** дополнительно нужен **Docker**:
  - доступ к Docker daemon (обычно `/var/run/docker.sock`)
  - право собирать и удалять образы (`docker build`, `docker rmi`)

Рекомендуется:
- Linux (из-за `fcntl`-lock и типичного окружения Docker/Trivy)

---

## Структура проекта

- `trivy-scanner.py` — основной скрипт
- `input_images.txt` — список удалённых образов + `severity=...`
- `input_images_files.txt` — список Dockerfile путей + `severity=...`
- `.trivy_cache/` — создаётся автоматически (Trivy cache + DB)
- `Docker_files/` — вспомогательная директория (в текущей версии скрипту не обязательна)

---

## Быстрый старт

### 1) Подготовьте входные файлы

#### Remote: `input_images.txt`
Пример:
```txt
# Уровень критичности: 1=UNKNOWN+, 2=LOW+, 3=MEDIUM+, 4=HIGH+, 5=CRITICAL
severity=4

# Docker образы для сканирования (лучше фиксировать digest)
ghcr.io/grafana/k6-operator:runner-v1.2.0@sha256:...
ghcr.io/grafana/k6-operator:starter-v1.2.0@sha256:...
```

#### Local: `input_images_files.txt`
Пример:
```txt
# Уровень критичности: 1=UNKNOWN+, 2=LOW+, 3=MEDIUM+, 4=HIGH+, 5=CRITICAL
severity=4

# Пути к Dockerfile (лучше абсолютные или относительные от директории запуска)
./path/to/Dockerfile
/home/user/projects/app/Dockerfile
```

---

### 2) Запуск

Интерактивное меню (если `--mode` не указан):
```bash
python3 trivy-scanner.py
```

Прямой запуск нужного режима:

**Remote:**
```bash
python3 trivy-scanner.py --mode remote
```

**Local:**
```bash
python3 trivy-scanner.py --mode local
```

**Both (remote + local):**
```bash
python3 trivy-scanner.py --mode both
```

---

## Параметры запуска

```bash
python3 trivy-scanner.py --help
```

Ключевые флаги:
- `--mode {remote,local,both}` — режим работы (если не указан — меню)
- `--jobs-remote N` — параллельность remote-скана (по умолчанию `2`)
- `--jobs-local N` — параллельность local-режима (build+scan) (по умолчанию `1`)
- `--trivy-timeout 10m` — timeout для Trivy (по умолчанию `10m`)

---

## Логика фильтрации по критичности (severity)

В файлах ввода задаётся `severity=1..5`:

| severity | что включается в отчёт |
|---:|---|
| 1 | `UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL` |
| 2 | `LOW, MEDIUM, HIGH, CRITICAL` |
| 3 | `MEDIUM, HIGH, CRITICAL` |
| 4 | `HIGH, CRITICAL` |
| 5 | `CRITICAL` |

---

## Что именно попадает в отчёт

Скрипт читает JSON, который генерирует Trivy, и собирает:
- **Vulnerabilities** (уязвимости пакетов)
- **Secrets** (секреты), если Trivy их возвращает в вашем режиме/версии

Затем группирует по:
1) **типу компонента**, который вычисляется из полей `Class/Type/Target` (например: `Debian-package`, `Go-package`, `NodeJS-package`, `Java-package`, `Secret`, …)
2) **Severity** (`CRITICAL`, `HIGH`, …)

---

## Формат итогового JSON (схема верхнего уровня)

Итоговый файл — это **массив объектов**, по одному объекту на просканированную цель.

### Remote элемент
```json
{
  "image": "registry.example.com/app@sha256:...",
  "scan_timestamp": "2026-02-17T12:34:56.789",
  "severity_level": 4,
  "included_severities": ["HIGH","CRITICAL"],
  "scan_type": "remote",

  "Debian-package": {
    "CRITICAL": [
      {
        "vuln_id": "CVE-2025-XXXX",
        "installed_vers": "1.2.3",
        "fixed": "1.2.4",
        "library": "libssl3",
        "type_detail": "debian",
        "class_detail": "os-pkgs",
        "target": "Debian 12.0 (bookworm)",
        "type": "vulnerability",
        "title": "...",
        "description": "...",
        "primaryurl": "..."
      }
    ]
  },

  "Secret": {
    "HIGH": [
      {
        "secret_id": "xxx",
        "category": "xxx",
        "title": "xxx",
        "target": "/path/in/layer",
        "start_line": 10,
        "end_line": 10,
        "match": "....",
        "type_detail": "filesystem",
        "class_detail": "secret",
        "type": "secret"
      }
    ]
  }
}
```

### Local элемент
Отличие: появляется `dockerfile` и образ формируется временно:
```json
{
  "dockerfile": "/abs/path/to/Dockerfile",
  "image": "local_scan_project_YYYYmmdd_HHMMSS_ffffff:latest",
  "scan_type": "local",
  "...": "..."
}
```

---

## Особенности local-режима (Dockerfile)

В local-режиме для каждого Dockerfile:
1) определяется директория Dockerfile (она используется как build context)
2) выполняется `docker build -q -f <Dockerfile> -t <temp_image> .`
3) образ сканируется через Trivy
4) образ удаляется `docker rmi -f <temp_image>`

Если сборка падает — в результат добавляется объект с `error`.

---

## Типовые проблемы и быстрые фиксы

### 1) Нет прав к Docker daemon (local-режим)
Симптомы: `permission denied`, `cannot connect to the Docker daemon`, `dial unix /var/run/docker.sock`.

Решение:
- добавьте пользователя в группу `docker` и перелогиньтесь, или
- запускайте скрипт от root, или
- используйте sudo там, где необходимо.

Скрипт **автоматически** повторяет Trivy-скан с `sudo`, если ошибка похожа на проблему прав.

### 2) Проблемы с Trivy DB (коррупция/недокачка)
Скрипт сам пытается сделать repair, но если нужно руками:
```bash
trivy clean --vuln-db --java-db
# или точечно:
rm -rf ./.trivy_cache/db ./.trivy_cache/java-db
```

### 3) Старая версия Trivy не поддерживает флаги
Скрипт делает fallback (перезапуск без неподдерживаемых флагов), если видит `unknown flag` для:
- `--no-progress`
- `--quiet`
- `--timeout`
- `--skip-db-update`
- `--skip-java-db-update`

---

## Примечания по безопасности

- Отчёт может содержать фрагменты, похожие на секреты (`match`). Храните результаты как чувствительные данные.
- В remote-режиме сканируются registry-артефакты: убедитесь, что у вас есть доступ и политика использования registry это допускает.

---

## Быстрый пример (pipeline-friendly)

Поскольку **stdout** печатает только имя файла, можно делать так:

```bash
REPORT="$(python3 trivy-scanner.py --mode remote --jobs-remote 4)"
echo "Saved report: $REPORT"
```
