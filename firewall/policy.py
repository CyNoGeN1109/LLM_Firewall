import re
from dataclasses import dataclass

_REQUEST = (
    r"(?:how\s+(?:to|do\s+i|can\s+i|would\s+i|could\s+i)|steps?\s+(?:to|for)|"
    r"guide\s+(?:to|on|for)|instructions?\s+(?:to|for|on)|teach\s+me\s+(?:to|how)|"
    r"show\s+me\s+how|walk\s+me\s+through|ways?\s+to|tutorial\s+(?:on|for)|"
    r"recipe\s+for|best\s+way\s+to|i\s+(?:want|need|would\s+like)\s+to|"
    r"give\s+me\s+(?:the\s+)?(?:steps?|instructions?|a\s+guide|a\s+recipe)\s+(?:to|for|on))"
)

_WEAPON = (
    r"\b(?:bombs?|explosives?|ieds?|grenades?|napalm|thermite|detonators?|"
    r"pipe\s*bombs?|dirty\s*bombs?|molotovs?|nerve\s*(?:agent|gas)|sarin|vx|tabun|"
    r"novichok|mustard\s*gas|ricin|anthrax|bioweapons?|biological\s*weapons?|"
    r"chemical\s*weapons?|meth(?:amphetamine)?|fentanyl|cocaine|heroin|silencers?|"
    r"suppressors?|ghost\s*guns?|c-?4|tnt|rdx|semtex)\b"
)

_MAKE = (
    r"\b(?:make|makes?|build|builds?|create|construct|assemble|synthesi[sz]e|"
    r"manufactur\w*|produc\w*|prepar\w*|cook|brew|3d\s*print)\b"
)

_CYBER_OBJ = (
    r"(?:hack\s+into|break\s+into|gain\s+(?:unauthorized\s+)?access\s+to|"
    r"ransomware|keyloggers?|spyware|rootkits?|botnets?|trojans?|computer\s+virus|"
    r"malware|phishing\s+(?:kit|page|email|site)|steal\w*\s+(?:passwords?|"
    r"credentials?|logins?)|crack\s+(?:a\s+|the\s+)?passwords?|ddos\s+attack|"
    r"brute\s*force\s+(?:attack|login)|sql\s+injection\s+(?:attack|payload))"
)

_CYBER_MAKE = (
    r"\b(?:write|create|build|code|develop|generate|deploy)\b[\s\S]{0,25}"
    r"\b(?:ransomware|keyloggers?|spyware|rootkits?|botnets?|trojans?|"
    r"computer\s+virus|malware\s+(?:that|to|which)|phishing\s+(?:kit|page|site))"
)

BLOCK_RULES = [
    {
        "id": "weapon_synthesis",
        "attack_type": "harmful_request",
        "severity": "high",
        "reason": "Request for instructions to make a weapon, explosive, or dangerous agent.",
        "pattern": re.compile(
            rf"(?:(?:{_REQUEST}[\s\S]{{0,60}})?{_MAKE}[\s\S]{{0,25}}{_WEAPON})"
            rf"|(?:(?:recipe|formula|blueprint|schematic)s?\s+(?:for|to\s+make)"
            rf"[\s\S]{{0,25}}{_WEAPON})",
            re.I,
        ),
    },
    {
        "id": "cyber_intrusion",
        "attack_type": "harmful_request",
        "severity": "high",
        "reason": "Request for instructions to perform an intrusion or build malware.",
        "pattern": re.compile(
            rf"(?:{_REQUEST}[\s\S]{{0,40}}{_CYBER_OBJ})|(?:{_CYBER_MAKE})",
            re.I,
        ),
    },
    {
        "id": "violence_against_person",
        "attack_type": "harmful_request",
        "severity": "high",
        "reason": "Request for instructions to harm a person or conceal a crime.",
        "pattern": re.compile(
            r"(?:" + _REQUEST + r"[\s\S]{0,40})?"
            r"\b(?:kill|murder|poison|strangle|stab|assassinate|torture)\b"
            r"[\s\S]{0,25}\b(?:someone|somebody|a\s+person|a\s+human|my\s+\w+|"
            r"him|her|them|people|my\s+(?:wife|husband|boss|neighbou?r))\b"
            r"|\bdispose\s+of\s+(?:a|the|his|her|my)\s+(?:body|corpse|remains)\b"
            r"|\bget\s+away\s+with\s+(?:murder|killing|a\s+crime)\b",
            re.I,
        ),
    },
    {
        "id": "evasion_concealment",
        "attack_type": "harmful_request",
        "severity": "high",
        "reason": "Request to make harm untraceable or evade detection.",
        "pattern": re.compile(
            r"\b(?:untraceable|undetectable|impossible\s+to\s+trace|"
            r"without\s+(?:getting\s+caught|being\s+detected|leaving\s+evidence))\b"
            r"[\s\S]{0,30}\b(?:poison|toxin|weapon|gun|bomb|kill|murder|attack|drug)\b"
            r"|\b(?:poison|weapon|method)\b[\s\S]{0,30}\b(?:untraceable|undetectable)\b",
            re.I,
        ),
    },
    {
        "id": "prompt_injection",
        "attack_type": "prompt_injection",
        "severity": "high",
        "reason": "Attempt to override or extract the system instructions.",
        "pattern": re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|discard)\b[\s\S]{0,30}"
            r"\b(?:all|any|the|your|these|previous|prior|earlier|above|initial|system)\b"
            r"[\s\S]{0,25}"
            r"\b(?:instructions?|rules?|prompts?|directions?|guidelines?|"
            r"constraints?|polic(?:y|ies)|restrictions?|filters?)\b"
            r"|\b(?:reveal|show|print|display|repeat|output|leak|expose)\b[\s\S]{0,30}"
            r"\b(?:system\s+prompt|initial\s+(?:instructions?|prompt)|"
            r"hidden\s+(?:prompt|instructions?)|your\s+(?:instructions?|system\s+prompt)|"
            r"the\s+prompt\s+above)\b"
            r"|\byou\s+are\s+now\b[\s\S]{0,20}"
            r"\b(?:dan|do\s+anything\s+now|developer\s+mode|jailbroken|unrestricted)\b",
            re.I,
        ),
    },
    {
        "id": "jailbreak_persona",
        "attack_type": "jailbreak_attempt",
        "severity": "high",
        "reason": "Attempt to adopt an unrestricted or rule-free persona.",
        "pattern": re.compile(
            r"\b(?:act\s+as|pretend\s+(?:to\s+be|you(?:'re| are))|roleplay\s+as|"
            r"imagine\s+you\s+are|simulate\s+(?:being|a)|behave\s+(?:as|like))\b"
            r"[\s\S]{0,45}"
            r"\b(?:unrestricted|no\s+restrictions?|no\s+rules?|no\s+filters?|"
            r"without\s+(?:any\s+)?(?:restrictions?|filters?|rules?|guidelines?)|"
            r"dan\b|do\s+anything\s+now|jailbroken|developer\s+mode|amoral|"
            r"uncensored|no\s+ethical|ignore\s+(?:all\s+)?(?:safety|guidelines))",
            re.I,
        ),
    },
    {
        "id": "csam",
        "attack_type": "harmful_request",
        "severity": "high",
        "reason": "Request involving sexual content with minors.",
        "pattern": re.compile(
            r"\b(?:child|children|minor|underage|pre-?teen|toddler|infant|"
            r"little\s+(?:boy|girl)|\d{1,2}\s*(?:yo|y/o|year[\s-]*old))\b"
            r"[\s\S]{0,25}"
            r"\b(?:porn\w*|nude|naked|sexual\w*|explicit|molest\w*|erotic|fondl\w*|nsfw)\b"
            r"|\b(?:porn\w*|nude|naked|sexual\w*|explicit|erotic)\b[\s\S]{0,25}"
            r"\b(?:child|children|minor|underage|pre-?teen|toddler)\b",
            re.I,
        ),
    },
]

SIGNAL_RULES = [
    {
        "id": "weapon_terms",
        "pattern": re.compile(
            r"\b(?:ricin|anthrax|sarin|vx|tabun|novichok|nerve\s+agent|bioweapon|"
            r"chemical\s+weapon|dirty\s+bomb|c-?4|tnt|rdx|semtex|cyanide|"
            r"poison|toxin|explosive)\b",
            re.I,
        ),
    },
    {
        "id": "self_harm_terms",
        "pattern": re.compile(
            r"\b(?:suicide|kill\s+myself|end\s+my\s+life|self[-\s]?harm|"
            r"overdose\s+on)\b",
            re.I,
        ),
    },
]


@dataclass
class PolicyHit:
    rule_id: str
    attack_type: str
    severity: str
    reason: str


def scan(normalized):
    for rule in BLOCK_RULES:
        for variant in normalized.variants:
            if rule["pattern"].search(variant):
                return PolicyHit(
                    rule["id"], rule["attack_type"], rule["severity"], rule["reason"]
                )
    return None


def signals(normalized):
    found = []
    for rule in SIGNAL_RULES:
        for variant in normalized.variants:
            if rule["pattern"].search(variant):
                found.append(rule["id"])
                break
    return found
