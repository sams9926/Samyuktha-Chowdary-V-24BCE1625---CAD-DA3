import io
import hmac
import hashlib

import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageOps

from config import SIGN_KEY

Image.MAX_IMAGE_PIXELS = 40_000_000     # refuse "decompression bombs"

MAGIC = 0xA5C3
PAYLOAD_BITS = 64                        # 16 magic + 32 id + 16 tag
ZW0, ZW1 = "\u200b", "\u200c"            # invisible zero-width characters


# ======================= payload =======================

def _tag(share_id: int) -> int:
    """Secret 16-bit tag. Without SIGN_KEY nobody can forge a valid payload."""
    mac = hmac.new(SIGN_KEY.encode(), b"fp:" + str(share_id).encode(), hashlib.sha256).digest()
    return int.from_bytes(mac[:2], "big")


def _payload_bits(share_id: int):
    if not 0 <= share_id < 2 ** 32:
        raise ValueError("share id out of range")
    s = format(MAGIC, "016b") + format(share_id, "032b") + format(_tag(share_id), "016b")
    return [int(c) for c in s]


def _decode_bits(bits):
    """64 bits -> share id, or None if marker/tag don't check out."""
    s = "".join(str(int(b)) for b in bits)
    if int(s[:16], 2) != MAGIC:
        return None
    sid = int(s[16:48], 2)
    if int(s[48:], 2) != _tag(sid):
        return None
    return sid


# ======================= images =======================

def _to_rgb(img):
    img = ImageOps.exif_transpose(img)           # respect phone-camera rotation
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        return Image.alpha_composite(bg, rgba).convert("RGB")
    return img.convert("RGB")


def _font(size):
    try:
        return ImageFont.load_default(size=size)  # Pillow 10.1+
    except TypeError:
        return ImageFont.load_default()


def watermark(img, text):
    """Faint diagonal tiled text with the recipient's name (visible deterrent)."""
    w, h = img.size
    size = max(14, w // 38)
    font = _font(size)

    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    l, t, r, b = probe.textbbox((0, 0), text, font=font)
    tile = Image.new("RGBA", (r - l + 20, b - t + 20), (0, 0, 0, 0))
    d = ImageDraw.Draw(tile)
    d.text((11 - l, 11 - t), text, font=font, fill=(0, 0, 0, 60))        # shadow
    d.text((10 - l, 10 - t), text, font=font, fill=(255, 255, 255, 75))  # text
    tile = tile.rotate(30, expand=True, resample=Image.BICUBIC)

    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    step_x, step_y = tile.width + size * 2, tile.height + size * 2
    for row, y in enumerate(range(-tile.height, h, step_y)):
        offset = (step_x // 2) if row % 2 else 0
        for x in range(-tile.width + offset, w, step_x):
            layer.paste(tile, (x, y))        # no mask: copies RGBA as-is (tiles never overlap)
    return Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")


def embed_id(img, share_id):
    """Hide the payload in the lowest bit of every pixel's red value, repeating."""
    bits = np.array(_payload_bits(share_id), dtype=np.uint8)
    arr = np.array(img.convert("RGB"))
    h, w = arr.shape[:2]
    red = arr[:, :, 0].flatten()
    red = (red & 0xFE) | np.resize(bits, red.size)    # pixel i carries bit (i % 64)
    arr[:, :, 0] = red.reshape(h, w)
    return Image.fromarray(arr)


def extract_id(img):
    """Read the lowest bits back, majority-vote each of the 64 positions."""
    arr = np.array(img.convert("RGB"))
    lsb = arr[:, :, 0].flatten() & 1
    n = (lsb.size // PAYLOAD_BITS) * PAYLOAD_BITS
    if n == 0:
        return None
    votes = (lsb[:n].reshape(-1, PAYLOAD_BITS).mean(axis=0) > 0.5).astype(int)
    # Try every cyclic shift, so crops that remove rows from the top still work
    for shift in range(PAYLOAD_BITS):
        sid = _decode_bits(np.roll(votes, shift).tolist())
        if sid is not None:
            return sid
    return None


def personalise_image(raw: bytes, recipient: str, share_id: int) -> bytes:
    img = _to_rgb(Image.open(io.BytesIO(raw)))
    img = watermark(img, recipient)               # watermark FIRST...
    if img.width * img.height >= PAYLOAD_BITS * 4:
        img = embed_id(img, share_id)             # ...then hide the ID (order matters)
    buf = io.BytesIO()
    img.save(buf, "PNG")                          # PNG is lossless: hidden bits survive
    return buf.getvalue()


# ======================= text =======================

def embed_text(text: str, share_id: int) -> str:
    text = text.replace(ZW0, "").replace(ZW1, "")      # drop any pre-existing marks
    mark = "".join(ZW1 if b else ZW0 for b in _payload_bits(share_id))
    lines = text.split("\n")
    cands = [i for i, line in enumerate(lines) if " " in line]
    if not cands:
        return mark + text
    if len(cands) > 50:                                # spread up to 50 marks evenly
        cands = cands[::len(cands) // 50][:50]
    for i in cands:
        j = lines[i].index(" ") + 1                    # right after the first word
        lines[i] = lines[i][:j] + mark + lines[i][j:]
    return "\n".join(lines)


def extract_text(text: str):
    zw = [1 if c == ZW1 else 0 for c in text if c in (ZW0, ZW1)][:20000]
    for i in range(len(zw) - PAYLOAD_BITS + 1):        # slide a 64-bit window
        sid = _decode_bits(zw[i:i + PAYLOAD_BITS])
        if sid is not None:
            return sid
    return None


# ======================= entry point used by /api/s/{id}/open =======================

def personalise(raw: bytes, mime: str, share: dict):
    rid = int(share["id"])
    label = str(share["recipient"])[:60]
    if mime.startswith("image/"):
        return personalise_image(raw, label, rid), "image/png"
    if mime == "text/plain":
        text = raw.decode("utf-8", errors="replace")
        return embed_text(text, rid).encode("utf-8"), "text/plain; charset=utf-8"
    raise ValueError("unsupported type")