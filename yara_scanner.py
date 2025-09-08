import yara
import os

class YaraScanner:
    def __init__(self, rules_path="rules/"):
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path):
        rule_files = {}
        for fname in os.listdir(path):
            if fname.endswith(".yar") or fname.endswith(".yara"):
                rule_files[fname] = os.path.join(path, fname)
        if rule_files:
            return yara.compile(filepaths=rule_files)
        return None

    def scan_file(self, filepath):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            return [m.rule for m in matches]
        except Exception as e:
            print(f"[YARA] Erro ao escanear {filepath}: {e}")
            return []