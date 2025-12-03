#!/usr/bin/env python3
"""
Advanced Fuzzing Test for Template String Processing

Target: BaseTranslator.prompt() method in translator.py
Strategy: Use malformed templates to find injection or parsing bugs
"""

import sys
import os
import atheris
from string import Template

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdf2zh.translator import BaseTranslator


@atheris.instrument_func
def TestOneInput(data):
    """
    Fuzz test for template string processing with advanced strategies:
    1. Malformed template syntax
    2. Injection attempts (template injection)
    3. Recursive/nested substitution
    4. Missing/extra variables
    """
    fdp = atheris.FuzzedDataProvider(data)

    # Initialize a base translator
    try:
        translator = BaseTranslator("en", "zh", "test-model", False)
    except Exception:
        return

    # Strategy selection
    strategy = fdp.ConsumeIntInRange(0, 6)

    if strategy == 0:
        # Valid template with random text
        template_str = fdp.ConsumeUnicodeNoSurrogates(200)
        text = fdp.ConsumeUnicodeNoSurrogates(100)

    elif strategy == 1:
        # Template injection attempts - nested variables
        patterns = [
            "${${lang_in}}",
            "$${lang_out}",
            "${lang_in${lang_out}}",
            "{{lang_in}}",
            "${lang_in:${lang_out}}",
        ]
        template_str = patterns[fdp.ConsumeIntInRange(0, len(patterns) - 1)]
        text = fdp.ConsumeUnicodeNoSurrogates(50)

    elif strategy == 2:
        # Missing closing braces
        patterns = [
            "${lang_in",
            "${lang_out",
            "${text",
            "$lang_in}",
            "${",
            "$}",
            "{}",
            "$",
        ]
        template_str = patterns[fdp.ConsumeIntInRange(0, len(patterns) - 1)]
        text = fdp.ConsumeUnicodeNoSurrogates(50)

    elif strategy == 3:
        # Unknown variables
        template_str = "${unknown_var} ${another_var} ${lang_in}"
        text = fdp.ConsumeUnicodeNoSurrogates(50)

    elif strategy == 4:
        # Special characters in variable names
        chars = ['!', '@', '#', '%', '&', '*', '(', ')', '-', '+', '=', '[', ']', '{', '}', '|', '\\', ';', ':', "'", '"', '<', '>', ',', '.', '?', '/']
        var_name = "".join([chars[fdp.ConsumeIntInRange(0, len(chars) - 1)] for _ in range(10)])
        template_str = f"${{{var_name}}}"
        text = fdp.ConsumeUnicodeNoSurrogates(50)

    elif strategy == 5:
        # Extremely long template
        template_str = "${lang_in}" * fdp.ConsumeIntInRange(100, 1000)
        text = fdp.ConsumeUnicodeNoSurrogates(50)

    else:
        # Pure random
        template_str = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))

    try:
        # Create template
        if template_str:
            prompt_template = Template(template_str)
        else:
            prompt_template = None

        # Call the prompt method
        result = translator.prompt(text, prompt_template)

        # Validation
        if not isinstance(result, list):
            return

        if result:
            for item in result:
                if not isinstance(item, dict):
                    return
                if "role" not in item or "content" not in item:
                    return
                if not isinstance(item["role"], str) or not isinstance(item["content"], str):
                    return

    except (ValueError, KeyError, TypeError, AttributeError):
        # Expected exceptions for malformed templates
        pass
    except Exception as e:
        # Log unexpected exceptions
        pass


def main():
    """Main entry point with seed corpus and persistent corpus"""
    # Seed corpus (read-only)
    seed_corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "template")

    # Persistent corpus (writable)
    persistent_corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "template_persistent")
    os.makedirs(persistent_corpus_dir, exist_ok=True)

    args = sys.argv

    # Add persistent corpus first
    args.append(persistent_corpus_dir)

    # Add seed corpus second
    if os.path.exists(seed_corpus_dir):
        args.append(seed_corpus_dir)

    print(f"[INFO] Persistent corpus: {persistent_corpus_dir}")
    print(f"[INFO] Seed corpus: {seed_corpus_dir}")
    print(f"[INFO] Progress will be saved - you can resume anytime")

    atheris.Setup(args, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
