This VSCode Marketplace extension is deprecated. Please use the version from the [OpenVSX Registry](https://open-vsx.org/extension/4ds/zator-vscode).

![logo](https://miro.medium.com/v2/resize\:fit:1400/1*wCSMfWVjeK8eqdfCe4SI0w.png)

# Zator

Специализированный язык программирования для генерации и обработки AI-контента

## 1. Введение

Zator — это специализированный язык программирования, предназначенный для создания и обработки AI-генерируемого контента (текста и изображений) с использованием API KoboldCpp. Язык предоставляет простой и интуитивно понятный синтаксис для построения генеративных пайплайнов с минимальным количеством кода, а также включает встроенные функции для постобработки изображений, HTTP-запросов и выполнения системных команд.

**Новое в версии 0.0.3:**

* Режим отладки (`debug mode`)
* Поддержка кастомных API endpoints
* Функции `open_txt` и `open_img`
* Вызов функций без `call`
* Единый интерпретатор для библиотек, функций и основного кода
* Исправлена передача параметров функций
* Исправлена интерполяция строк
* Исправлен timeout генерации текста
* Переработан модуль `request` (удалена зависимость от консоли)
* Исправлены `save_txt` и `save_img` (корректные пути)
* Удалён `context`

## 2. Системные требования и настройка

### Требования

* **ОС:** Windows 10/11, Linux, macOS
* **Зависимости:**

  * Запущенный экземпляр KoboldCpp с включенными API:

    * `/api/v1/generate` — для генерации текста
    * `/sdapi/v1/txt2img` — для генерации изображений (требуется поддержка Stable Diffusion)
  * Библиотеки: `libpng`, `zlib`, `curl` для обработки изображений и HTTP-запросов
  * **Аппаратное обеспечение:** Доступ к GPU рекомендуется для генерации изображений

### Запуск

```bash
zator file.zator [--debug]
```

### Настройка сервера

По умолчанию используется локальный сервер:

```zator
@server_url = "http://localhost:5001"
```

Можно использовать свой сервер:

```zator
@server_url = "http://192.168.0.10:8080"
```

Custom endpoints можно указывать отдельно для каждого вызова генерации:

```zator
var story = generate_text("Напиши рассказ", 200, "/api/v3/generate_text/")
var image = generate_img("Fantasy castle", 512, 512, "/unstable_diffusion/")
```

Endpoint в функциях генерации необязателен.

### Режим отладки

```bash
zator file.zator --debug
```

В режиме отладки интерпретатор выводит:

* Выполняемые команды
* Ошибки интерполяции
* HTTP-запросы
* Пути к файлам
* Ошибки генерации

## 3. Синтаксис языка

### 3.1. Комментарии

```zator
# Это однострочный комментарий
```

### 3.2. Переменные и типы данных

Zator поддерживает три типа переменных:

**Текст (`VAR_STRING`)**

```zator
var greeting = "Привет, мир!"
var story = generate_text("Напишите короткую историю о кобольде", 200)
```

**Целое число (`VAR_INT`)**

```zator
var counter = 42
var score = 85
```

**Изображение (`VAR_IMAGE`)**

```zator
var portrait = generate_img("Портрет дружелюбного кобольда, цифровое искусство", 512, 512)
```

### 3.3. F-строки

F-строки позволяют встраивать переменные и функции внутрь строк. Синтаксис: `{имя_переменной/функция с параметрами}`.

```zator
var username = "Алексей"
var current_date = "2026-05-12"
print("Привет, {username}! Сегодняшняя дата: {current_date}")
```
Вот пример с функцией:

```zator
def current_date(date){
   return date
}
var username = "Алексей"
print("Привет, {username}! Сегодняшняя дата: {current_date(2026-05-12)}")
```

**F-строки работают:**

* В присваиваниях (`var x = "Привет, {name}"`)
* В аргументах функций (`print`, `save_txt`, `save_img`, `generate_text`, `generate_img`, `request`, `exec_cmd`, `open_txt`, `open_img`)
* В путях к файлам
* В промптах
* В параметрах функций

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

if score > 80 and level == "expert" {
    print("Отличный результат для эксперта!")
}
```

**Поддерживаемые операторы сравнения:**

* `==`, `!=` — для строк и чисел
* `>`, `<`, `>=`, `<=` — только для целых чисел

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

Функции позволяют группировать код и повторно использовать его.

**Синтаксис определения:**

```zator
def function_name(param1, param2, ...) {
    # тело функции
}
```

**Синтаксис вызова:**

```zator
function_name(arg1, arg2)
```

**Примеры:**

```zator
# Без параметров

def greet() {
    print("Привет, мир!\n")
}

greet()

# С одним параметром

def greet_user(name) {
    print("Привет, {name}!\n")
}

greet_user("Алексей")
greet_user("Мария")

# С несколькими параметрами

def create_character(name, char_class, background) {
    var prompt = "Портрет персонажа: {name}, класс: {char_class}, {background}"
    var character = generate_img(prompt, 512, 512)

    save_img(character, "characters/{name}.png")
    print("Персонаж {name} создан!\n")
}

create_character("Гаррет", "Вор", "тёмный переулок")
create_character("Элеонора", "Маг", "башня волшебника")
```

**Параметры:**

* До 10 параметров на функцию
* Параметры передаются по значению
* Поддерживают f-строки
* Тип: строка (автоматическое преобразование из int)

### 3.6. Импорт файлов

Команда `#import` позволяет включить код из другого `.zator` файла в текущий скрипт.

```zator
#import "utils.zator"
#import "api_calls.zator"

some_util_function()
```

## 4. Функции генерации контента

### 4.1. Генерация текста

```zator
var result = generate_text(prompt, max_tokens)
```

или:

```zator
var result = generate_text(prompt, max_tokens, endpoint)
```

**Параметры:**

* `prompt` — строка или имя переменной с промптом
* `max_tokens` — максимальное количество генерируемых токенов
* `endpoint` — кастомный endpoint (необязательно)

**Пример:**

```zator
var story = generate_text("Напиши рассказ про космического кобольда", 200)
print(story)
```

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
var image = generate_img(prompt, width, height)
```

или:

```zator
var image = generate_img(prompt, width, height, endpoint)
```

**Параметры:**

* `prompt` — описание изображения
* `width`, `height` — размеры в пикселях
* `endpoint` — кастомный endpoint (необязательно)

**Пример:**

```zator
var image = generate_img("Фэнтези город ночью", 512, 512)
save_img(image, "city.png")
```

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

* `source_image` — исходное изображение
* `x`, `y` — координаты пикселя с цветом для обрезки
* `tolerance` — допуск в процентах (опционально)

**Пример:**

```zator
var photo = generate_img("Фотография на зеленом фоне", 512, 512)
var subject = chroma_key_crop(photo, 10, 10, 5.0)

save_img(subject, "output/subject.png")
```

### 5.2. Масштабирование изображения

```zator
var scaled = scale_to(source_image, width, height)
```

**Пример:**

```zator
var icon = scale_to(subject, 128, 128)
save_img(icon, "output/icon.png")
```

## 6. Работа с файлами

### 6.1. Сохранение текста

```zator
save_txt(variable, "files/output.txt")
```

### 6.2. Сохранение изображений

```zator
save_img(variable, "images/output.png")
```

### 6.3. Открытие текстовых файлов

```zator
var story_text = open_txt("data/story.txt")
print(story_text)
```

Функция читает текстовый файл и возвращает содержимое как строку.

### 6.4. Открытие изображений

```zator
var image = open_img("images/character.png")
```

Функция загружает PNG-изображение в переменную типа `VAR_IMAGE`.

### 6.5. Ввод данных

```zator
input(username)
print("Здравствуйте, {username}!")
```

Функция `input()` читает одну строку из stdin.

## 7. HTTP-запросы (API)

### 7.1. Выполнение запросов

```zator
var response
request(url, method, response [, body])
```

**Параметры:**

* `url` — адрес API
* `method` — HTTP-метод (`GET`, `POST`, `PUT`, `DELETE`)
* `response` — переменная для ответа
* `body` — тело запроса (опционально)

**GET-запрос:**

```zator
var response
request("https://api.example.com/status", "GET", response)

print(response)
```

**POST-запрос:**

```zator
var json_body = "{ \"text\": \"Hello\" }"

var response
request("https://api.example.com/send", "POST", response, json_body)
```

## 8. Системные команды

### 8.1. Выполнение команд командной строки

```zator
var output = exec_cmd("command")
```

или:

```zator
exec_cmd("command", output_var)
```

**Примеры:**

```zator
var files = exec_cmd("ls -la")
print("Files: {files}")

var filename = "data.txt"
var content = exec_cmd("cat {filename}")
print(content)
```

**⚠️ Предупреждение о безопасности:**
Используйте `exec_cmd` осторожно при работе с пользовательским вводом.

## 9. Вспомогательные функции

### 9.1. Вставка C-кода

```zator
emit_c("embedded/example.c")
```

Сохраняет встроенный пример C-кода в указанный путь.

## 10. Примеры использования

### Пример 1: Генерация персонажа

```zator
var character_prompt = "Игровой персонаж кобольд-маг в фэнтези сеттинге"

var character_img = generate_img(character_prompt, 512, 512)

save_img(character_img, "characters/cobold_mag.png")

print("Персонаж успешно создан!")
```

### Пример 2: Работа с функциями

```zator
def greet(name, age) {
    print("Привет, {name}! Вам {age} лет.\n")
}

def create_file(filename, content) {
    save_txt(content, "output/{filename}.txt")
}

greet("Алексей", 25)
greet("Мария", 30)

create_file("report", "Отчёт за месяц")
```

### Пример 3: Открытие файлов

```zator
var story = open_txt("stories/story.txt")
print(story)

var image = open_img("images/hero.png")
save_img(image, "backup/hero_copy.png")
```

### Пример 4: Работа с API

```zator
var token = "YOUR_BOT_TOKEN"
var chat_id = "YOUR_CHAT_ID"
var message_text = "Hello from Zator!"

var message_body = "{ \"chat_id\": \"{chat_id}\", \"text\": \"{message_text}\" }"

var api_url = "https://api.telegram.org/bot{token}/sendMessage"

var telegram_response
request(api_url, "POST", telegram_response, message_body)

print(telegram_response)
```

### Пример 5: Debug mode

```zator
debug = true

var result = generate_text("Напиши тестовый текст", 100)
print(result)
```

## 11. Ограничения и рекомендации

### Текущие ограничения:

* Условные блоки поддерживают только одну команду после условия (если не используются `{}`)
* Циклы не поддерживают вложенные `repeat`
* Все пути относительные
* Для генерации изображений требуется работающий SD API
* `exec_cmd` требует осторожности при работе с пользовательским вводом

### Рекомендации:

* Используйте изображения кратные 64 пикселям
* Используйте умеренные значения `max_tokens`
* Проверяйте пути при работе с файлами
* Используйте `debug = true` при отладке
* Используйте функции для переиспользования кода

## 12. Поддержка и развитие

Если вы обнаружили ошибку или хотите предложить улучшение:

1. Убедитесь, что API KoboldCpp запущен
2. Проверьте вывод debug mode
3. Создайте issue в репозитории проекта

### Планы развития:

* Поддержка массивов и списков
* JSON-парсер
* Наложение изображений
* Интеграция с другими AI API
* Улучшенная система модулей
* Оптимизация памяти

## 13. История версий

| Версия | Дата       | Изменения                                                                                                                                                                                                                                           |
| ------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0.0.3  | 2026-05-12 | Debug mode, custom API endpoints, open_txt/open_img, вызов функций без call, единый интерпретатор, исправления параметров функций, интерполяции строк, timeout генерации текста, переработка request, исправления save_txt/save_img, удалён context |
| 0.0.2  | 2026-02-20 | Функции, параметры функций, импорт библиотек, HTTP-запросы, exec_cmd, исправлен порядок выполнения                                                                                                                                                  |
| 0.0.1  | 2025-12-15 | Добавлена обработка изображений (chroma_key, scale)                                                                                                                                                                                                 |
| 0.0.0  | 2025-10-01 | Первая версия с генерацией текста и изображений                                                                                                                                                                                                     |

---

**Версия документации:** 0.0.3
**Дата обновления:** 12 мая 2026 г.
