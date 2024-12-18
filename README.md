# Auth gRPC Service

## Описание

**Auth Service** — интегрируемый gRPC-сервис для авторизации пользователей. Он поддерживает регистрацию, вход в систему, валидацию JWT токенов и проверку административных привилегий пользователей.

### Основные возможности:
- **Регистрация пользователей:** Хранение информации для последующей аутентификации.
- **Вход в систему:** Выдача JWT токенов для доступа к защищенным ресурсам.
- **Валидация токенов:** Проверка действительности токенов и предоставление информации о пользователе.
- **Проверка привилегий:** Определение, является ли пользователь администратором.

Сервис может быть использован в веб-приложениях, API-шлюзах, мобильных приложениях и других проектах с распределенной архитектурой.

---

## Структура API

### Сервис `Auth`

#### Методы:

1. **Register**  
   Регистрирует нового пользователя.  
   **Вход:**
    - `email` (string) — Email пользователя.
    - `password` (string) — Пароль пользователя.  
      **Выход:**
    - `user_id` (int64) — Уникальный идентификатор пользователя.

2. **Login**  
   Аутентифицирует пользователя и выдает JWT токен.  
   **Вход:**
    - `email` (string) — Email пользователя.
    - `password` (string) — Пароль пользователя.
    - `app_id` (int32) — Идентификатор приложения.  
      **Выход:**
    - `token` (string) — JWT токен.

3. **IsAdmin**  
   Проверяет, является ли пользователь администратором.  
   **Вход:**
    - `user_id` (int64) — Идентификатор пользователя.  
      **Выход:**
    - `is_admin` (bool) — Является ли пользователь администратором.

4. **ValidateToken**  
   Проверяет валидность JWT токена.  
   **Вход:**
    - `token` (string) — JWT токен.
    - `app_id` (int32) — Идентификатор приложения.  
      **Выход:**
    - `user_id` (string) — Уникальный идентификатор пользователя.
    - `email` (string) — Email пользователя.
    - `is_valid` (bool) — Валидность токена.

---

### Технологии:
- **gRPC:** Для определения API и коммуникации.
- **Protocol Buffers:** Для сериализации данных.
- **JWT:** Для защиты и проверки подлинности запросов.

---

## Как запустить?

### Требования:
- Go 1.21+
- gRPC & Protocol Buffers
- Docker (опционально)

### Запуск локально:
1. Установите зависимости:
   ```bash
   go mod tidy
2. Примените файлы миграции через команду:
   ```bash
   task migrate
3. Затем запустите сам сервис
    ```bash
   task auth