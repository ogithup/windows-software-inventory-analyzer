from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable


@dataclass(slots=True)
class TrayCallbacks:
    on_show: Callable[[], None]
    on_exit: Callable[[], None]


class DesktopTrayController:
    def __init__(self, app_name: str, callbacks: TrayCallbacks) -> None:
        self.app_name = app_name
        self.callbacks = callbacks
        self._icon = None
        self._thread: threading.Thread | None = None

    def is_supported(self) -> bool:
        try:
            import pystray  # noqa: F401
            from PIL import Image  # noqa: F401
            return True
        except Exception:
            return False

    def start(self) -> bool:
        if self._icon is not None:
            return True
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception:
            return False

        def show_action(icon, item) -> None:  # type: ignore[no-untyped-def]
            self.callbacks.on_show()

        def exit_action(icon, item) -> None:  # type: ignore[no-untyped-def]
            self.callbacks.on_exit()

        image = self._build_image(Image, ImageDraw)
        menu = pystray.Menu(
            pystray.MenuItem("Pencereyi Goster", show_action),
            pystray.MenuItem("Cikis", exit_action),
        )
        self._icon = pystray.Icon("wsia", image, self.app_name, menu)
        self._thread = threading.Thread(target=self._icon.run, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        if self._icon is None:
            return
        try:
            self._icon.stop()
        except Exception:
            pass
        self._icon = None
        self._thread = None

    def notify(self, title: str, message: str) -> bool:
        if self._icon is None:
            return False
        try:
            self._icon.notify(message, title)  # type: ignore[attr-defined]
            return True
        except Exception:
            return False

    @staticmethod
    def _build_image(Image, ImageDraw):  # type: ignore[no-untyped-def]
        image = Image.new("RGBA", (64, 64), (15, 118, 110, 255))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((6, 6, 58, 58), radius=12, fill=(15, 118, 110, 255))
        draw.rectangle((18, 16, 46, 48), fill=(255, 253, 248, 255))
        draw.line((22, 24, 42, 24), fill=(15, 118, 110, 255), width=4)
        draw.line((22, 32, 42, 32), fill=(15, 118, 110, 255), width=4)
        draw.line((22, 40, 34, 40), fill=(15, 118, 110, 255), width=4)
        return image
