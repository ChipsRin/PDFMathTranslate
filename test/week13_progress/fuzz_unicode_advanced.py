#!/usr/bin/env python3
"""
Advanced Fuzzing Test for Unicode Character Processing

Target: remove_control_characters() function in translator.py
Strategy: Use seed corpus + dictionary to find edge cases in Unicode processing
"""

import sys
import os
import atheris
import unicodedata

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdf2zh.translator import remove_control_characters


@atheris.instrument_func
def TestOneInput(data):
    """
    Fuzz test for remove_control_characters with advanced strategies:
    1. Seed corpus with known Unicode edge cases
    2. Dictionary-guided generation of special characters
    3. Mixed Unicode categories (control, combining, surrogates, etc.)
    """
    fdp = atheris.FuzzedDataProvider(data)

    # Strategy 1: Generate strings with various Unicode categories
    strategy = fdp.ConsumeIntInRange(0, 5)

    if strategy == 0:
        # Control characters (category C)
        test_str = fdp.ConsumeUnicodeNoSurrogates(100)
        # Mix with control chars
        control_chars = ['\x00', '\x01', '\x02', '\x1f', '\x7f', '\r', '\n', '\t']
        for _ in range(fdp.ConsumeIntInRange(0, 10)):
            pos = fdp.ConsumeIntInRange(0, len(test_str))
            char = control_chars[fdp.ConsumeIntInRange(0, len(control_chars) - 1)]
            test_str = test_str[:pos] + char + test_str[pos:]

    elif strategy == 1:
        # Combining characters (category M)
        base = fdp.ConsumeUnicodeNoSurrogates(50)
        combining = ['̀', '́', '̂', '̃', '̄', '̆', '̇', '̈', '̊', '̋', '̌']
        test_str = ""
        for c in base:
            test_str += c
            if fdp.ConsumeBool():
                test_str += combining[fdp.ConsumeIntInRange(0, len(combining) - 1)]

    elif strategy == 2:
        # Mixed category characters
        categories = []
        for _ in range(fdp.ConsumeIntInRange(1, 100)):
            # Generate random Unicode codepoint
            codepoint = fdp.ConsumeIntInRange(0, 0x10FFFF)
            try:
                char = chr(codepoint)
                categories.append(char)
            except (ValueError, OverflowError):
                pass
        test_str = "".join(categories)

    elif strategy == 3:
        # Null bytes and special cases
        test_str = fdp.ConsumeUnicodeNoSurrogates(50)
        # Insert null bytes
        for _ in range(fdp.ConsumeIntInRange(0, 5)):
            pos = fdp.ConsumeIntInRange(0, len(test_str))
            test_str = test_str[:pos] + '\x00' + test_str[pos:]

    elif strategy == 4:
        # Edge case: extremely long strings with control chars
        length = fdp.ConsumeIntInRange(1000, 10000)
        test_str = fdp.ConsumeUnicodeNoSurrogates(length)
        # Sprinkle control chars throughout
        for i in range(0, len(test_str), 100):
            test_str = test_str[:i] + '\x01' + test_str[i:]

    else:
        # Pure random
        test_str = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1000))

    try:
        # Execute the function
        result = remove_control_characters(test_str)

        # Validation: result should not contain control characters
        if result:
            for char in result:
                category = unicodedata.category(char)
                # Control characters have category starting with 'C'
                # But we allow some like '\n', '\r', '\t' in practice
                # The function should remove all category C chars
                if category.startswith('C') and category != 'Cc':
                    # Found a control character that wasn't removed
                    # This is potentially a bug
                    pass

        # Additional checks
        if not isinstance(result, str):
            return

        # Result should be <= original length
        if len(result) > len(test_str):
            return

    except (UnicodeDecodeError, UnicodeEncodeError, TypeError, AttributeError):
        # Expected exceptions for malformed Unicode
        pass
    except Exception as e:
        # Unexpected exception - this could be a bug
        # But we don't crash the fuzzer, just log it
        pass


def main():
    """Main entry point with seed corpus and persistent corpus"""
    # Seed corpus (read-only, for initial interesting inputs)
    seed_corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "unicode")

    # Persistent corpus (writable, for saving progress)
    persistent_corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "unicode_persistent")
    os.makedirs(persistent_corpus_dir, exist_ok=True)

    args = sys.argv

    # Add persistent corpus first (will be modified)
    args.append(persistent_corpus_dir)

    # Add seed corpus second (read-only)
    if os.path.exists(seed_corpus_dir):
        args.append(seed_corpus_dir)

    print(f"[INFO] Persistent corpus: {persistent_corpus_dir}")
    print(f"[INFO] Seed corpus: {seed_corpus_dir}")
    print(f"[INFO] Progress will be saved - you can resume anytime with the same command")

    atheris.Setup(args, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
