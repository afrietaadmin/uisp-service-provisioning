import requests
import logging
import re


def escape_markdown(text: str) -> str:
    """Escape special Markdown characters for Telegram.

    Escapes: *, _, `, [, ], (, ), #, +, -, ., !
    These characters have special meaning in Markdown and need to be escaped
    with a backslash to display literally.

    Args:
        text: Text to escape

    Returns:
        Text with special Markdown characters escaped
    """
    # Characters that need escaping in Telegram Markdown
    special_chars = r'[*_`\[\]()#+\-.]'
    return re.sub(special_chars, r'\\\g<0>', text)


class TelegramNotifier:
    """Telegram notification sender."""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def send(self, message: str, level: str = "info"):
        """Send a formatted message to Telegram.

        Automatically escapes special Markdown characters in the message
        to prevent parsing errors.
        """
        if not self.bot_token or not self.chat_id:
            logging.warning("Telegram credentials missing; skipping notification.")
            return False

        prefix = "✅" if level == "info" else "❌" if level == "error" else "⚠️"
        # Escape the message content to prevent Markdown parsing errors
        escaped_message = escape_markdown(message)

        payload = {
            "chat_id": self.chat_id,
            "text": f"{prefix} {escaped_message}",
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
