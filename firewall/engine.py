from dataclasses import dataclass, field

from . import classifier, config, policy
from .normalize import normalize


@dataclass
class Decision:
    allowed: bool
    risk: str
    attack_type: str
    reason: str
    layer: str
    rule_id: str = "none"
    confidence: float = 0.0
    signals: list = field(default_factory=list)
    raw: str = ""


def _last_user_message(messages):
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "") or ""
    return ""


def _recent_user_text(messages, turns):
    user_turns = [
        m.get("content", "") or "" for m in messages if m.get("role") == "user"
    ]
    if not user_turns:
        return ""
    return "\n".join(user_turns[-turns:])


def _to_bool(value, default=True):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "allow", "allowed")
    if value is None:
        return default
    return bool(value)


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def inspect(messages, system_prompt=""):
    last = _last_user_message(messages)
    context = _recent_user_text(messages, config.CONTEXT_TURNS)

    for target in (system_prompt or "", context, last):
        if not target:
            continue
        hit = policy.scan(normalize(target))
        if hit:
            return Decision(
                allowed=False,
                risk=hit.severity,
                attack_type=hit.attack_type,
                reason=hit.reason,
                layer="policy",
                rule_id=hit.rule_id,
                confidence=0.99,
                signals=policy.signals(normalize(last)),
            )

    detected_signals = policy.signals(normalize(last))

    try:
        parsed, raw = classifier.classify(last)
    except classifier.ClassifierError as exc:
        if config.FAIL_MODE == "open":
            return Decision(
                allowed=True,
                risk="low",
                attack_type="none",
                reason="Classifier unavailable; configured to fail open.",
                layer="fail-open",
                signals=detected_signals,
            )
        return Decision(
            allowed=False,
            risk="medium",
            attack_type="classifier_unavailable",
            reason=f"Classifier unavailable; failing closed ({exc}).",
            layer="fail-closed",
            confidence=0.5,
            signals=detected_signals,
        )

    allowed = _to_bool(parsed.get("allowed"))
    risk = str(parsed.get("risk", "low")).lower()
    if risk not in ("low", "medium", "high"):
        risk = "medium"
    attack_type = parsed.get("attack_type") or "none"
    reason = parsed.get("reason") or "Classifier decision."
    confidence = _to_float(parsed.get("confidence"))

    if allowed and detected_signals and risk == "low":
        risk = "medium"

    return Decision(
        allowed=allowed,
        risk=risk,
        attack_type="none" if allowed else attack_type,
        reason=reason,
        layer="classifier",
        confidence=confidence,
        signals=detected_signals,
        raw=raw,
    )
