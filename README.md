# Zator

Специализированный язык программирования для генерации и обработки AI-контента

## 1. Введение

Zator — это специализированный язык программирования, предназначенный для создания и обработки AI-генерируемого контента (текста и изображений) с использованием API KoboldCpp. Язык предоставляет простой и интуитивно понятный синтаксис для построения генеративных пайплайнов с минимальным количеством кода, а также включает встроенные функции для постобработки изображений и выполнения системных команд.

**Новое в версии 0.0.2:**
- Функции араметры функций (как в Python)
- Исправленный порядок выполнения кода
- Функция `exec_cmd` для выполнения команд командной строки
- Улучшенная поддержка f-строк во всех функциях
- HTTP-запросы
- Кросплатформенность

## 2. Системные требования и настройка

### Требования

*   **ОС:** Windows 10/11, Linux, macOS
*   **Зависимости:**
    *   Запущенный экземпляр KoboldCpp с включенными API:
        *   `/api/v1/generate` — для генерации текста
        *   `/sdapi/v1/txt2img` — для генерации изображений (требуется поддержка Stable Diffusion)
    *   Библиотеки: `libpng`, `zlib`, `curl` для обработки изображений и HTTP-запросов
    *   **Аппаратное обеспечение:** Доступ к GPU рекомендуется для генерации изображений

### Запуск

```bash
zator.exe ваш_скрипт.zator
```

### Настройка сервера

По умолчанию используется локальный сервер:

```zator
server = "http://localhost:5001"
```

## 3. Синтаксис языка

### 3.1. Комментарии и контекст

```zator
# Это однострочный комментарий

context = "Вы — помощник, специализирующийся на создании творческого контента."
```

Контекст используется во всех вызовах генерации как префикс к промпту.

### 3.2. Переменные и типы данных

Zator поддерживает три типа переменных:

**Текст (`VAR_STRING`)**
```zator
var greeting = "Привет, мир!"
var story = generate_text("Напишите короткую историю о кобольде", context, 200)
```

**Целое число (`VAR_INT`)**
```zator
var counter = 42
var score = 85
```

**Изображение (`VAR_IMAGE`)**
```zator
var portrait = generate_img("Портрет дружелюбного кобольда, цифровое искусство", context, 512, 512)
```

### 3.3. F-строки

F-строки позволяют встраивать значения переменных внутрь строк. Синтаксис: `{имя_переменной}`.

```zator
var username = "Алексей"
var current_date = "2026-02-20"
print("Привет, {username}! Сегодняшняя дата: {current_date}")
```

**F-строки работают:**
- В присваиваниях (`var x = "Привет, {name}"`)
- В аргументах функций (`print`, `save_txt`, `save_img`, `generate_text`, `generate_img`, `request`, `exec_cmd`)
- В путях к файлам
- В контексте и промптах
- В параметрах функций

**Для вывода литеральных фигурных скобок используйте экранирование:**
```zator
var text = "Используйте \{variable\} для подстановки"
```

### 3.4. Управляющие конструкции

**Условные операторы**
```zator
if score > 80 {
    print("Отличный результат!")
} else if score > 60 {
    print("Хороший результат!")
} else {
    print("Нужно улучшить результат.")
}

# Поддержка двух условий, соединенных 'and'
if score > 80 and level == "expert" {
    print("Отличный результат для эксперта!")
}
```

**Поддерживаемые операторы сравнения:**
- `==`, `!=` — для строк и чисел
- `>`, `<`, `>=`, `<=` — только для целых чисел

**Циклы**
```zator
var countdown = 5
repeat 10 {
    countdown = countdown - 1
    print("Осталось времени: {countdown}")
    if countdown <= 0 {
        print("Цикл прерван досрочно")
        break
    }
}
```

Ключевое слово `break` немедленно прерывает выполнение цикла.

### 3.5. Функции (User-Defined)

Функции позволяют группировать код и повторно использовать его. **Поддерживаются параметры как в Python.**

**Синтаксис определения:**
```zator
def function_name(param1, param2, ...) {
    # тело функции
}
```

**Синтаксис вызова:**
```zator
call function_name(arg1, arg2, ...)
```

**Примеры:**
```zator
# Без параметров
def greet {
    print("Привет, мир!\n")
}
call greet()

# С одним параметром
def greet_user(name) {
    print("Привет, {name}!\n")
}
call greet_user("Алексей")
call greet_user("Мария")

# С несколькими параметрами
def create_character(name, char_class, background) {
    var prompt = "Портрет персонажа: {name}, класс: {char_class}, {background}"
    var character = generate_img(prompt, context, 512, 512)
    save_img(character, "characters/{name}.png")
    print("Персонаж {name} создан!\n")
}

call create_character("Гаррет", "Вор", "тёмный переулок")
call create_character("Элеонора", "Маг", "башня волшебника")

# С f-строками в аргументах
var prefix = "Сэр"
call greet_user("{prefix} Артур")
```

**Параметры:**
- До 10 параметров на функцию
- Параметры передаются по значению (копируются в локальные переменные)
- Поддерживают f-строки
- Тип: строка (автоматическое преобразование из int)

**Ограничения:**
- Рекурсия обнаруживается и блокируется (защита от бесконечного цикла)
- Параметры функции становятся локальными переменными на время выполнения
- При вложенных вызовах значения параметров сохраняются и восстанавливаются

### 3.6. Импорт файлов

Команда `#import` позволяет включить код из другого `.zator` файла в текущий скрипт.

```zator
#import "utils.zator"
#import "api_calls.zator"

# Используем функции или переменные из импортированных файлов
call some_util_function
```

## 4. Функции генерации контента

### 4.1. Генерация текста

```zator
var result = generate_text(prompt, context, max_tokens)
```

**Параметры:**
- `prompt` — строка или имя переменной с промптом
- `context` — контекст, объединяется с промптом
- `max_tokens` — максимальное количество генерируемых токенов

**Используемые параметры API (KoboldCpp):**
```json
{
  "max_length": max_tokens,
  "max_context_length": 2048,
  "temperature": 0.7,
  "top_p": 0.9,
  "top_k": 100,
  "rep_pen": 1.1,
  "use_default_badwordsids": false
}
```

### 4.2. Генерация изображений

```zator
var image = generate_img(prompt, context, width, height)
```

**Параметры:**
- `prompt` — описание изображения
- `context` — контекст (может использоваться в f-строках)
- `width`, `height` — размеры в пикселях (рекомендуется кратно 64)

**Используемые параметры API (Stable Diffusion через KoboldCpp):**
```json
{
    "prompt": "...",
    "negative_prompt": "ugly, deformed, noisy, blurry, distorted",
    "width": 512,
    "height": 512,
    "sampler_name": "Euler a",
    "steps": 20,
    "cfg_scale": 7.0,
    "seed": -1
}
```

## 5. Функции обработки изображений

### 5.1. Обрезка по цвету (Chroma Key)

```zator
var cropped = chroma_key_crop(source_image, x, y[, tolerance])
```

**Параметры:**
- `source_image` — исходное изображение
- `x`, `y` — координаты пикселя с цветом для обрезки
- `tolerance` (опционально) — допуск в процентах (0.0-100.0), по умолчанию 0.0

**Описание:**
Функция обрезает изображение по указанному цвету, делая пиксели этого цвета прозрачными и обрезая пустые границы. Цвет определяется по пикселю с координатами (x, y).

**Пример:**
```zator
var photo = generate_img("Фотография на зеленом фоне", context, 512, 512)
var subject = chroma_key_crop(photo, 10, 10, 5.0)
save_img(subject, "output/subject.png")
```

### 5.2. Масштабирование изображения

```zator
var scaled = scale_to(source_image, width, height)
```

**Параметры:**
- `source_image` — исходное изображение
- `width`, `height` — целевые размеры в пикселях

**Описание:**
Функция масштабирует изображение до указанных размеров с использованием ближайшего соседа (nearest neighbor) для сохранения четкости.

**Пример:**
```zator
var icon = scale_to(subject, 128, 128)
save_img(icon, "output/icon.png")
```

## 6. Работа с файлами

### 6.1. Сохранение текста

```zator
save_txt(variable, "относительный/путь/к/файлу.txt")
```

### 6.2. Сохранение изображений

```zator
save_img(variable, "images/fantasy_landscape.png")
```

**Особенности:**
- Файлы сохраняются относительно директории, в которой находится запускаемый `.zator`-скрипт
- Изображения сохраняются в формате PNG
- Если переменная содержит обработанное изображение (после `chroma_key_crop` или `scale_to`), используется внутреннее представление

### 6.3. Ввод данных

```zator
input(username)
print("Здравствуйте, {username}!")
```

Функция `input()` читает одну строку из stdin (без приглашения).

## 7. HTTP-запросы (API)

### 7.1. Выполнение запросов

```zator
var response
request(url, method, response [, body])
```

**Параметры:**
- `url` — адрес конечной точки API
- `method` — HTTP-метод (`GET`, `POST`, `PUT`, `DELETE`)
- `response` — переменная строки, в которую будет записан ответ сервера
- `body` (опционально) — тело запроса (используется для `POST` и `PUT`)

**Примеры:**

**GET-запрос:**
```zator
var response
request("https://api.example.com/status", "GET", response)
print(response)
```

**POST-запрос с телом:**
```zator
var token = "7505891802:AAEQIroV99TUnk_3hgIgxnMf7RnHjz5jjVg"
var chat_id = "5917034332"
var message = "Hello pigger"
var json_body = "{ \"chat_id\": \"{chat_id}\", \"text\": \"{message}\" }"

var api_url = "https://api.telegram.org/bot{token}/sendMessage"

var response
request(api_url, "POST", response, json_body)
print(response)
```

## 8. Системные команды

### 8.1. Выполнение команд командной строки

```zator
var output = exec_cmd("command")
# или
exec_cmd("command", output_var)
```

**Параметры:**
- `command` — команда для выполнения (поддерживает f-строки)
- `output_var` — переменная для сохранения вывода

**Примеры:**
```zator
# Получить список файлов
var files = exec_cmd("ls -la")
print("Files: {files}")

# Команда с переменной
var filename = "data.txt"
var content = exec_cmd("cat {filename}")
print("Content: {content}")

# Альтернативный синтаксис
exec_cmd("pwd", current_dir)
print("Directory: {current_dir}")

# Конвейеры команд
var process_info = exec_cmd("ps aux | grep {filename} | head -5")
print("Process info: {process_info}")
```

**⚠️ Предупреждение о безопасности:**
Используйте `exec_cmd` с осторожностью, особенно с пользовательским вводом, чтобы избежать инъекций команд.

## 9. Вспомогательные функции

### 9.1. Вставка C-кода

```zator
emit_c("embedded/example.c")
```

Сохраняет встроенный пример C-кода в указанный путь.

## 10. Примеры использования

### Пример 1: Генерация персонажа и его обработка

```zator
context = "Вы — дизайнер игровых персонажей."

# Генерация персонажа на зеленом фоне
var character_prompt = "Игровой персонаж кобольд-маг в фэнтези сеттинге, чистый зеленый фон"
var character_img = generate_img(character_prompt, context, 512, 512)

# Обрезка по зеленому фону
var character_cropped = chroma_key_crop(character_img, 10, 10, 3.0)

# Создание разных размеров для использования в игре
var character_icon = scale_to(character_cropped, 64, 64)
var character_preview = scale_to(character_cropped, 256, 256)

# Сохранение результатов
save_img(character_cropped, "characters/cobold_mag.png")
save_img(character_icon, "characters/icons/cobold_mag.png")
save_img(character_preview, "characters/previews/cobold_mag.png")

print("Персонаж успешно создан и обработан!")
```

### Пример 2: Функции с параметрами

```zator
# Библиотека функций
def greet(name, age) {
    print("Привет, {name}! Вам {age} лет.\n")
}

def create_file(filename, content) {
    save_txt(content, "output/{filename}.txt")
    print("Файл {filename}.txt создан!\n")
}

# Основной скрипт
context = "Демонстрация функций"

call greet("Алексей", 25)
call greet("Мария", 30)

var text = "Тестовое содержимое"
call create_file("test", text)
call create_file("report", "Отчёт за месяц")
```

### Пример 3: Использование exec_cmd

```zator
# Работа с файловой системой
var filename = "data.txt"
var directory = "documents"

# Проверка существования файла
var check = exec_cmd("test -f {filename} && echo 'exists' || echo 'missing'")

if check == "exists" {
    var content = exec_cmd("cat {filename}")
    print("File content: {content}")
} else {
    print("File {filename} not found!")
}

# Получение информации о системе
var os_info = exec_cmd("uname -a")
print("OS: {os_info}")

# Текущая директория
exec_cmd("pwd", current_dir)
print("Working in: {current_dir}")
```

### Пример 4: Интерактивный генератор контента

```zator
context = "Вы — помощник по созданию контента."

print("Введите своё имя: ")
input(username)
print("Привет, {username}! Выберите тип контента: ")
print("1 — Текстовая история")
print("2 — Изображение персонажа")
input(choice)

if choice == "1" {
    print("Введите тему истории: ")
    input(theme)
    var prompt = "Напишите короткую историю на тему '{theme}' в стиле фэнтези."
    var tokens = 250
    var content = generate_text(prompt, context, tokens)
    print("\nВаша история:\n{content}")

    print("\nСохранить в файл? (да/нет) ")
    input(save_choice)
    if save_choice == "да" {
        save_txt(content, "stories/{username}_{theme}.txt")
    }
}

if choice == "2" {
    print("Введите описание персонажа: ")
    input(description)
    var prompt = "Портрет персонажа: {description}, цифровое искусство"
    var character_img = generate_img(prompt, context, 512, 512)
    save_img(character_img, "characters/{username}_character.png")
    print("Изображение сохранено!")
}
```

### Пример 5: Вызов внешнего API (Telegram Bot)

```zator
var token = "YOUR_BOT_TOKEN"
var chat_id = "YOUR_CHAT_ID"
var message_text = "Hello from Zator!"

# Формируем тело запроса с f-строками
var message_body = "{ \"chat_id\": \"{chat_id}\", \"text\": \"{message_text}\" }"

# Формируем URL
var api_url = "https://api.telegram.org/bot{token}/sendMessage"

# Выполняем запрос
var telegram_response
request(api_url, "POST", telegram_response, message_body)

print("Telegram API response: {telegram_response}")
```

## 11. Ограничения и рекомендации

### Текущие ограничения:
- Условные блоки поддерживают только одну команду после условия (если не используются скобки `{}`)
- Циклы не поддерживают вложенные `repeat`
- Все пути — относительные, базовая директория определяется как папка скрипта
- Для генерации изображений обязательно наличие работающего SD API в KoboldCpp
- Функция `request` требует установленного `curl` в системе
- Функция `exec_cmd` требует осторожности с пользовательским вводом (риск инъекций)

### Рекомендации:
- Размеры изображений должны быть кратны 64 пикселям для лучшей совместимости с VRAM
- Используйте умеренные значения `max_tokens` (до 500) для стабильной работы
- Для `chroma_key_crop` выбирайте пиксели в углах изображения для определения цвета фона
- Последовательная обработка: сначала обрежьте фон, затем масштабируйте
- При работе с `request` и JSON-телами убедитесь, что тело корректно сформировано и экранировано
- Используйте функции с параметрами для повторного использования кода

## 12. Поддержка и развитие

Если вы обнаружили ошибку или хотите предложить улучшение:
1. Убедитесь, что KoboldCpp запущен с нужными API
2. Проверьте логи и ответы от `curl`
3. Создайте issue в репозитории проекта с подробным описанием проблемы

### Планы развития:
- Поддержка вложенных условных блоков
- Добавление функций для наложения изображений
- Интеграция с другими AI API (DALL-E, Midjourney)
- Оптимизация памяти для работы с большими изображениями
- Улучшение безопасности при передаче данных в `request` и `exec_cmd`
- Встроенный JSON-парсер
- Поддержка массивов и списков

## 13. История версий

| Версия | Дата | Изменения |
|--------|------|-----------|
| 0.0.2 | 2026-02-20 | Функции, параметры функций, импорт библиотек, HTTP-запросы, exec_cmd, исправлен порядок выполнения |
| 0.0.1 | 2025-12-15 | Добавлена обработка изображений (chroma_key, scale) |
| 0.0.0 | 2025-10-01 | Первая версия с генерацией текста и изображений |

---

**Версия документации:** 0.0.2
**Дата обновления:** 20 февраля 2026 г.    - `/sdapi/v1/txt2img` — для генерации изображений (требуется поддержка Stable Diffusion)
  - Библиотеки: `libpng` для обработки изображений
- **Аппаратное обеспечение**: Доступ к GPU рекомендуется для генерации изображений
