import requests
import logging


class TelegramNotifier:
    """Telegram notification sender."""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def send(self, message: str, level: str = "info"):
        """Send a formatted message to Telegram."""
        if not self.bot_token or not self.chat_id:
            logging.warning("Telegram credentials missing; skipping notification.")
            return False

        prefix = "✅" if level == "info" else "❌" if level == "error" else "⚠️"
        payload = {
            "chat_id": self.chat_id,
            "text": f"{prefix} {message}",
            "parse_mode": "Markdown"
        }
        try:
            r = requests.post(self.base_url, json=payload, timeout=10)
            if r.status_code == 200:
                logging.info(f"Telegram message sent: {message}")
                return True
            else:
                logging.error(f"Telegram API error {r.status_code}: {r.text}")
                return False
        except Exception as e:
            logging.error(f"Telegram send failed: {e}")
            return False
