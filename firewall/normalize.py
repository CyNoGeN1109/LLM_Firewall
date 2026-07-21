import base64
import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E], None
)

CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ϲ": "c",
    "ι": "i", "κ": "k", "ѡ": "w", "ⅼ": "l", "ⅰ": "i", "ｇ": "g",
}

LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
})

_whitespace = re.compile(r"\s+")
_base64_token = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_punct_run = re.compile(r"\w(?:[._\-*/~]+\w){2,}")


@dataclass
class Normalized:
    original: str
    canonical: str
    variants: tuple


def _strip_zero_width(text):
    return text.translate(ZERO_WIDTH)


def _map_confusables(text):
    return "".join(CONFUSABLES.get(ch, ch) for ch in text)


def canonical(text):
    text = unicodedata.normalize("NFKC", text or "")
    text = _strip_zero_width(text)
    text = _map_confusables(text)
    text = text.lower()
    return _whitespace.sub(" ", text).strip()


def _deleet(text):
    return text.translate(LEET)


def _despace(text):
    return _punct_run.sub(
        lambda m: re.sub(r"[._\-*/~]+", "", m.group(0)), text
    )


def _decode_base64(text):
    decoded = []
    for token in _base64_token.findall(text):
        padding = "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token + padding, validate=True)
            candidate = raw.decode("utf-8")
        except Exception:
            continue
        if not candidate:
            continue
        readable = sum(ch.isprintable() or ch.isspace() for ch in candidate)
        if readable / len(candidate) > 0.85:
            decoded.append(candidate)
    return decoded


def normalize(text):
    canon = canonical(text)
    raw_variants = [
        canon,
        _deleet(canon),
        _despace(canon),
        _despace(_deleet(canon)),
    ]
    for decoded in _decode_base64(text or ""):
        dc = canonical(decoded)
        raw_variants.append(dc)
        raw_variants.append(_despace(dc))
    ordered = list(dict.fromkeys(v for v in raw_variants if v))
    return Normalized(text or "", canon, tuple(ordered))
