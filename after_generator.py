import os
import re
import shutil

source_models_path = "./tatrapayplus_generated/tatrapayplus_client/models"
target_models_path = "./tatrapayplus/models"
generated_root = "./tatrapayplus_generated"

os.makedirs(target_models_path, exist_ok=True)

# --- REGEXES ---

validator_pattern = re.compile(
    r"^\s*@field_validator\([^\n]+\)\n"
    r"(?:(?!^\s*@).*\n)*?"
    r"^\s*def [^\n]+\n"
    r"(?:^\s{4}.*\n?)*",
    re.MULTILINE,
)

orphan_enum_pattern = re.compile(
    r"^\s*if value not in set\(\[[^\]]+\]\):\n"
    r"\s*raise ValueError\([^)]+\)\n"
    r"\s*return value\n?",
    re.MULTILINE,
)

orphan_regex_pattern = re.compile(
    r"^\s*if not re\.match\(\s*r?[\"'].*?[\"']\s*,\s*value\s*\):\n"
    r"\s*raise ValueError\([^)]+\)\n"
    r"\s*return value\n?",
    re.MULTILINE,
)

import_replace_pattern = re.compile(
    r"^from tatrapayplus_client\.models(\..*) import ",
    re.MULTILINE,
)

unused_import_pattern = re.compile(
    r"^\s*(import re|from pydantic import field_validator)\s*$",
    re.MULTILINE,
)

# --- to_dict() block for actual_instance models ---
to_dict_code = (
    "    def to_dict(self) -> Union[str, Dict[str, Any]]:\n"
    "        \"\"\"Return the raw JSON-compatible representation of the actual_instance\"\"\"\n"
    "        if isinstance(self.actual_instance, str):\n"
    "            return self.actual_instance\n"
    "        elif hasattr(self.actual_instance, \"to_dict\"):\n"
    "            return self.actual_instance.to_dict()\n"
    "        elif hasattr(self.actual_instance, \"model_dump\"):\n"
    "            return self.actual_instance.model_dump(by_alias=True, exclude_none=True)\n"
    "        return self.actual_instance\n\n"
    "\n"
    "    def model_dump(self, *args, **kwargs):\n"
    "        return self.to_dict()\n\n"
)


# --- MAIN LOOP ---
for filename in os.listdir(source_models_path):
    if filename.endswith(".py") and filename != "__init__.py":
        source_path = os.path.join(source_models_path, filename)
        target_path = os.path.join(target_models_path, filename)

        with open(source_path, "r", encoding="utf-8") as f:
            content = f.read()

        original = content

        # Clean up
        content = re.sub(validator_pattern, "", content)
        content = re.sub(orphan_enum_pattern, "", content)
        content = re.sub(orphan_regex_pattern, "", content)
        content = re.sub(unused_import_pattern, "", content)
        content = re.sub(import_replace_pattern, r"from tatrapayplus.models\1 import ", content)

        # Inject to_dict() for actual_instance models
        if "actual_instance" in content and "def to_dict" not in content:
            class_match = re.search(r"(class\s+\w+\(BaseModel\):)", content)
            if class_match:
                insert_after = content.find('\n', class_match.end()) + 1
                content = content[:insert_after] + to_dict_code + content[insert_after:]

        # Save to destination
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"✅ Cleaned and moved: {filename}")

# Delete generated folder
if os.path.exists(generated_root):
    shutil.rmtree(generated_root)
    print(f"🗑️ Deleted folder: {generated_root}")
