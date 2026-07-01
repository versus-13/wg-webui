package web

import (
	"fmt"
	"net/http"
)

// knownLangs lists all supported language codes.
// To add a new language: add its code here and a new entry in translations below.
var knownLangs = map[string]bool{"en": true, "ru": true}

var translations = map[string]map[string]string{
	"en": {
		// navigation
		"nav.settings":    "Settings",
		"nav.status":      "Status",
		"nav.logout":      "Logout",
		"nav.back":        "← Back",
		"nav.back_peers":  "← Back to Peers",

		// page titles
		"page.peers":           "Peers — WireGuard UI",
		"page.login":           "Login — WireGuard",
		"page.setup_password":  "Set Password — WireGuard UI",
		"page.change_password": "Change Password — WireGuard UI",
		"page.settings":        "Settings — WireGuard UI",
		"page.status":          "Status — WireGuard",
		"page.config":          "Config %s — WireGuard",

		// labels / form text
		"label.password":         "Password",
		"label.new_password":     "New password",
		"label.confirm":          "Confirm password",
		"label.current_password": "Current password",
		"label.name":             "Name",
		"label.name_hint":        "Name (latin letters, digits, dash)",
		"label.ip":               "IP address (leave blank for auto-assign)",
		"label.host":             "Host (endpoint for clients)",
		"label.host_hint":        "Public address or domain of the WireGuard server, used in client configs.",
		"label.dns":              "DNS servers",
		"label.dns_hint":         "Comma-separated, used in client configs.",
		"label.setup_hint":       "Set a password to access the admin panel.",

		// buttons
		"btn.login":           "Login",
		"btn.add":             "+ Add",
		"btn.create":          "Create",
		"btn.cancel":          "Cancel",
		"btn.save":            "Save",
		"btn.set_password":    "Set Password",
		"btn.change_password": "Change Password",
		"btn.config":          "Config",
		"btn.disable":         "Disable",
		"btn.enable":          "Enable",
		"btn.delete":          "Delete",
		"btn.download":        "↓ Download .conf",

		// stats / misc UI
		"msg.total_peers":    "Total peers",
		"msg.active":         "Active",
		"msg.iface":          "Interface",
		"msg.peers":          "Peers",
		"msg.active_badge":   "active",
		"msg.disabled_badge": "disabled",
		"msg.created":        "Created",
		"msg.no_peers":       "No peers yet. Add the first one!",
		"msg.new_peer":       "New Peer",
		"msg.scan_qr":        "Scan the QR code in the WireGuard app",
		"msg.no_status":      "No data (WireGuard not running?)",

		// confirm dialogs
		"confirm.delete_peer": "Delete peer %s?",

		// sections
		"section.server":   "Server parameters",
		"section.security": "Security",
		"section.change_pw": "Change Password",

		// flash messages
		"flash.settings_saved":      "Settings saved",
		"flash.password_set":        "Password set. Please log in.",
		"flash.password_changed":    "Password changed successfully",
		"flash.err.no_password":     "No password set",
		"flash.err.wrong_password":  "Wrong password",
		"flash.err.empty_password":  "Password cannot be empty",
		"flash.err.passwords_match": "Passwords do not match",
		"flash.err.hash_error":      "Password hashing error",
		"flash.err.save_error":      "Save error: %v",
		"flash.err.invalid_name":    "Invalid name",
		"flash.err.peer_exists":     "Peer %q already exists",
		"flash.err.no_free_ip":      "No free IP addresses",
		"flash.err.keygen":          "Key generation error: %v",
		"flash.err.peer_save":       "Save error: %v",
		"flash.err.wg_reload":       "Peer created, but WireGuard reload failed: %v",
		"flash.err.peer_not_found":  "Peer not found",
		"flash.err.config_gen":      "Config generation error: %v",
		"flash.peer_enabled":        "Peer %q enabled",
		"flash.peer_disabled":       "Peer %q disabled",
		"flash.err.peer_delete":     "Delete error: %v",
		"flash.peer_deleted":        "Peer %q deleted",
		"flash.err.wg_not_updated":  "Peer deleted, but WireGuard not updated: %v",
		"flash.err.wrong_current_pw": "Wrong current password",
		"flash.err.empty_new_pw":    "New password cannot be empty",
	},
	"ru": {
		// navigation
		"nav.settings":    "Настройки",
		"nav.status":      "Статус",
		"nav.logout":      "Выйти",
		"nav.back":        "← Назад",
		"nav.back_peers":  "← Вернуться к пирам",

		// page titles
		"page.peers":           "Пиры — WireGuard UI",
		"page.login":           "Вход — WireGuard",
		"page.setup_password":  "Установка пароля — WireGuard UI",
		"page.change_password": "Смена пароля — WireGuard UI",
		"page.settings":        "Настройки — WireGuard UI",
		"page.status":          "Статус — WireGuard",
		"page.config":          "Конфиг %s — WireGuard",

		// labels / form text
		"label.password":         "Пароль",
		"label.new_password":     "Новый пароль",
		"label.confirm":          "Подтверждение",
		"label.current_password": "Текущий пароль",
		"label.name":             "Имя",
		"label.name_hint":        "Имя (только латиница, цифры, дефис)",
		"label.ip":               "IP-адрес (оставьте пустым — выберется автоматически)",
		"label.host":             "Хост (endpoint для клиентов)",
		"label.host_hint":        "Публичный адрес или домен WireGuard-сервера, используется в конфигах клиентов.",
		"label.dns":              "DNS-серверы",
		"label.dns_hint":         "Через запятую, используются в конфигах клиентов.",
		"label.setup_hint":       "Установите пароль для доступа к административной панели.",

		// buttons
		"btn.login":           "Войти",
		"btn.add":             "+ Добавить",
		"btn.create":          "Создать",
		"btn.cancel":          "Отмена",
		"btn.save":            "Сохранить",
		"btn.set_password":    "Установить пароль",
		"btn.change_password": "Сменить пароль",
		"btn.config":          "Конфиг",
		"btn.disable":         "Откл",
		"btn.enable":          "Вкл",
		"btn.delete":          "Удалить",
		"btn.download":        "↓ Скачать .conf",

		// stats / misc UI
		"msg.total_peers":    "Всего пиров",
		"msg.active":         "Активны",
		"msg.iface":          "Интерфейс",
		"msg.peers":          "Пиры",
		"msg.active_badge":   "активен",
		"msg.disabled_badge": "отключён",
		"msg.created":        "Создан",
		"msg.no_peers":       "Пиров пока нет. Добавьте первый!",
		"msg.new_peer":       "Новый пир",
		"msg.scan_qr":        "Отсканируйте QR-код в приложении WireGuard",
		"msg.no_status":      "Нет данных (WireGuard не запущен?)",

		// confirm dialogs
		"confirm.delete_peer": "Удалить пира %s?",

		// sections
		"section.server":    "Параметры сервера",
		"section.security":  "Безопасность",
		"section.change_pw": "Смена пароля",

		// flash messages
		"flash.settings_saved":      "Настройки сохранены",
		"flash.password_set":        "Пароль установлен. Войдите в систему.",
		"flash.password_changed":    "Пароль успешно изменён",
		"flash.err.no_password":     "Пароль не установлен",
		"flash.err.wrong_password":  "Неверный пароль",
		"flash.err.empty_password":  "Пароль не может быть пустым",
		"flash.err.passwords_match": "Пароли не совпадают",
		"flash.err.hash_error":      "Ошибка хеширования пароля",
		"flash.err.save_error":      "Ошибка сохранения: %v",
		"flash.err.invalid_name":    "Недопустимое имя",
		"flash.err.peer_exists":     "Пир «%s» уже существует",
		"flash.err.no_free_ip":      "Нет свободных IP-адресов",
		"flash.err.keygen":          "Ошибка генерации ключей: %v",
		"flash.err.peer_save":       "Ошибка сохранения: %v",
		"flash.err.wg_reload":       "Пир создан, но не удалось обновить WireGuard: %v",
		"flash.err.peer_not_found":  "Пир не найден",
		"flash.err.config_gen":      "Ошибка генерации конфига: %v",
		"flash.peer_enabled":        "Пир «%s» включён",
		"flash.peer_disabled":       "Пир «%s» отключён",
		"flash.err.peer_delete":     "Ошибка удаления: %v",
		"flash.peer_deleted":        "Пир «%s» удалён",
		"flash.err.wg_not_updated":  "Пир удалён, но WireGuard не обновлён: %v",
		"flash.err.wrong_current_pw": "Неверный текущий пароль",
		"flash.err.empty_new_pw":    "Новый пароль не может быть пустым",
	},
}

// translate returns the translation for key in lang, falling back to English,
// then the key itself.
func translate(lang, key string) string {
	if m, ok := translations[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := translations["en"]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// getLang reads the lang cookie and returns a known language code (default "en").
func getLang(r *http.Request) string {
	c, err := r.Cookie("lang")
	if err == nil && knownLangs[c.Value] {
		return c.Value
	}
	return "en"
}

// tf translates key using the request's language, then optionally formats it
// with fmt.Sprintf if args are provided.
func tf(r *http.Request, key string, args ...any) string {
	s := translate(getLang(r), key)
	if len(args) > 0 {
		s = fmt.Sprintf(s, args...)
	}
	return s
}
