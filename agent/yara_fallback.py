import re
import os

class YaraFallback:
    """
    A lightweight fallback for YARA when the yara-python library is unavailable.
    Parses .yar files and uses regex for string matching.
    """
    def __init__(self, rule_path):
        self.rules = []
        self.load_rules(rule_path)

    def load_rules(self, path):
        if not os.path.exists(path):
            return

        with open(path, 'r') as f:
            content = f.read()

        # Simple parser for "Strings" section
        # rule Name { strings: $s1 = "..." condition: ... }
        rule_blocks = re.findall(r'rule\s+(\w+)\s*\{([^}]+)\}', content)
        for name, body in rule_blocks:
            strings = re.findall(r'\$(\w+)\s*=\s*"([^"]+)"', body)
            self.rules.append({
                "name": name,
                "patterns": [(id, re.escape(val)) for id, val in strings]
            })

    def match_text(self, text):
        matches = []
        for rule in self.rules:
            detected = []
            for id, pattern in rule["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    detected.append(id)
            
            if detected:
                matches.append({
                    "rule": rule["name"],
                    "matched_strings": detected
                })
        return matches

    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                return self.match_text(content)
        except:
            return []
