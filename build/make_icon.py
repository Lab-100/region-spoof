# -*- coding: utf-8 -*-
"""Генерация иконки приложения Region Spoof (build/app.ico)."""
import os
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.ico")


def make(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size
    # тёмно-синий круг-подложка
    d.ellipse([1, 1, s - 1, s - 1], fill=(30, 58, 138, 255))
    d.ellipse([3, 3, s - 3, s - 3], outline=(148, 163, 184, 255), width=max(1, s // 64))
    # «лампочка»: жёлтая голова с нитью
    hw = s * 0.30
    y0 = s * 0.30
    d.ellipse([s / 2 - hw, y0, s / 2 + hw, y0 + 2 * hw], fill=(250, 204, 21, 255))
    # блик
    d.ellipse([s / 2 - hw * 0.45, y0 + hw * 0.18, s / 2, y0 + hw * 0.75], fill=(255, 240, 150, 255))
    # цоколь
    d.rectangle([s / 2 - hw * 0.55, y0 + 2 * hw, s / 2 + hw * 0.55, y0 + 2 * hw + s * 0.07], fill=(203, 213, 225, 255))
    # ножка/контакт внизу
    d.line([s / 2, y0 + 2 * hw + s * 0.07, s / 2, s * 0.62], fill=(203, 213, 225, 255), width=max(2, s // 32))
    return img


def main():
    imgs = [make(s) for s in (256, 128, 64, 48, 32, 16)]
    imgs[0].save(
        OUT,
        format="ICO",
        sizes=[(i.width, i.height) for i in imgs],
        append_images=imgs[1:],
    )
    print("Иконка сохранена:", OUT, os.path.getsize(OUT), "байт")


if __name__ == "__main__":
    main()