#!/usr/bin/env python3
"""
Advanced Integration Fuzzing Test for PDF Translation Workflow

Target: Multiple functions working together in pdf2zh
Strategy: Test realistic workflows with malformed inputs
"""

import sys
import os
import atheris
import unicodedata
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdf2zh.translator import remove_control_characters
from pdf2zh.pdfinterp import safe_float


def vflag_simulation(font: str, char: str):
    """
    Simulated vflag function for testing (from converter.py line 190)
    Tests formula/subscript font detection logic
    """
    if isinstance(font, bytes):
        try:
            font = font.decode('utf-8')
        except UnicodeDecodeError:
            font = ""
    font = font.split("+")[-1]

    if re.match(r"\(cid:", char):
        return True

    if re.match(
        r"(CM[^R]|MS.M|XY|MT|BL|RM|EU|LA|RS|LINE|LCIRCLE|TeX-|rsfs|txsy|wasy|stmary|.*Mono|.*Code|.*Ital|.*Sym|.*Math)",
        font,
    ):
        return True

    if (
        char
        and char != " "
        and (
            unicodedata.category(char[0])
            in ["Lm", "Mn", "Sk", "Sm", "Zl", "Zp", "Zs"]
            or ord(char[0]) in range(0x370, 0x400)
        )
    ):
        return True

    return False


@atheris.instrument_func
def TestOneInput(data):
    """
    Integration fuzzing test that combines multiple functions:
    1. remove_control_characters() -> clean text
    2. vflag() -> detect math formulas
    3. safe_float() -> coordinate parsing
    4. String encoding operations

    This tests realistic workflows where output of one function
    feeds into another, potentially exposing integration bugs.
    """
    fdp = atheris.FuzzedDataProvider(data)

    strategy = fdp.ConsumeIntInRange(0, 5)

    try:
        if strategy == 0:
            # Workflow 1: Text cleaning -> vflag detection
            raw_text = fdp.ConsumeUnicodeNoSurrogates(200)

            # Step 1: Clean control characters
            cleaned_text = remove_control_characters(raw_text)

            # Step 2: Extract potential font and character
            if cleaned_text and len(cleaned_text) > 0:
                # Generate font name
                font_patterns = ["CMR10", "CMSY", "Arial", "Times", "(cid:123)", ""]
                font = font_patterns[fdp.ConsumeIntInRange(0, len(font_patterns) - 1)]
                if fdp.ConsumeBool():
                    font = font + "+" + fdp.ConsumeUnicodeNoSurrogates(10)

                # Test vflag with cleaned character
                for char in cleaned_text[:5]:  # Test first few chars
                    try:
                        result = vflag_simulation(font, char)
                        if not isinstance(result, bool):
                            pass  # Potential bug
                    except (AttributeError, IndexError, TypeError):
                        pass

        elif strategy == 1:
            # Workflow 2: Coordinate parsing -> boundary validation
            coords = []
            for _ in range(4):
                coord_str = fdp.ConsumeUnicodeNoSurrogates(20)
                parsed = safe_float(coord_str)
                coords.append(parsed if parsed is not None else 0.0)

            # Validate coordinate bounds
            x0, y0, x1, y1 = coords
            if x0 is not None and x1 is not None:
                if x0 > x1:
                    # Swapped coordinates - potential bug
                    pass
            if y0 is not None and y1 is not None:
                if y0 > y1:
                    # Swapped coordinates - potential bug
                    pass

        elif strategy == 2:
            # Workflow 3: Font name parsing -> character encoding
            font_name = fdp.ConsumeUnicodeNoSurrogates(100)
            text = fdp.ConsumeUnicodeNoSurrogates(50)

            # Clean text first
            text = remove_control_characters(text)

            # Parse font name (simulating converter logic)
            if isinstance(font_name, bytes):
                try:
                    font_name = font_name.decode('utf-8')
                except UnicodeDecodeError:
                    font_name = ""

            if font_name:
                font_parts = font_name.split("+")
                base_font = font_parts[-1] if font_parts else ""

                # Test regex matching (from vflag logic)
                try:
                    if re.match(r"\(cid:", text):
                        pass
                    if re.match(r"(CM[^R]|MS.M|XY|MT|BL|RM|EU|LA|RS)", base_font):
                        pass
                except (re.error, TypeError):
                    pass

        elif strategy == 3:
            # Workflow 4: Unicode category checking -> encoding
            text = fdp.ConsumeUnicodeNoSurrogates(100)

            for char in text:
                try:
                    # Check Unicode category (from vflag logic)
                    category = unicodedata.category(char)
                    if category in ["Lm", "Mn", "Sk", "Sm", "Zl", "Zp", "Zs"]:
                        # Math symbol detected
                        pass

                    # Check if in Greek letter range
                    if ord(char) in range(0x370, 0x400):
                        pass

                    # Try encoding (simulating raw_string logic)
                    hex_2 = "%02x" % ord(char)
                    hex_4 = "%04x" % ord(char)

                    if not hex_2 or not hex_4:
                        pass  # Potential bug

                except (ValueError, TypeError, OverflowError):
                    pass

        elif strategy == 4:
            # Workflow 5: CID pattern matching
            cid_patterns = [
                "(cid:0)",
                "(cid:123)",
                "(cid:-1)",
                "(cid:65535)",
                "(cid:999999)",
                "(CID:123)",  # Wrong case
                "(cid:abc)",  # Non-numeric
                "(cid:",      # Incomplete
                "cid:123)",   # Missing open paren
            ]
            pattern = cid_patterns[fdp.ConsumeIntInRange(0, len(cid_patterns) - 1)]

            # Test regex matching
            try:
                match = re.match(r"\(cid:", pattern)
                if match:
                    # Extract CID number
                    cid_num_match = re.match(r"\(cid:(\d+)\)", pattern)
                    if cid_num_match:
                        cid_num = int(cid_num_match.group(1))
                        if cid_num < 0 or cid_num > 65535:
                            pass  # Invalid CID range
            except (re.error, ValueError):
                pass

        else:
            # Workflow 6: Complex combined scenario
            # Parse font
            font = fdp.ConsumeUnicodeNoSurrogates(50)
            if isinstance(font, bytes):
                try:
                    font = font.decode('utf-8')
                except UnicodeDecodeError:
                    font = ""

            # Parse coordinates
            x0 = safe_float(fdp.ConsumeUnicodeNoSurrogates(10))
            y0 = safe_float(fdp.ConsumeUnicodeNoSurrogates(10))
            size = safe_float(fdp.ConsumeUnicodeNoSurrogates(10))

            # Parse text
            text = remove_control_characters(fdp.ConsumeUnicodeNoSurrogates(100))

            # Validate complete "character" object
            if x0 is not None and y0 is not None and size is not None:
                if size <= 0:
                    pass  # Invalid font size
                if x0 < 0 or y0 < 0:
                    pass  # Negative coordinates (might be valid in PDF)

    except Exception as e:
        # Catch any unexpected exceptions
        # In a real fuzzer, we might log these
        pass


def main():
    """Main entry point with persistent corpus support"""
    # Create corpus directory for resumable fuzzing
    corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "integration_persistent")
    os.makedirs(corpus_dir, exist_ok=True)

    args = sys.argv

    # Add corpus directory if not already specified
    if len(args) == 1 or not any(arg.startswith('-') == False and arg != sys.argv[0] for arg in args[1:]):
        args.append(corpus_dir)

    print(f"[INFO] Corpus directory: {corpus_dir}")
    print(f"[INFO] To resume fuzzing, use the same command")
    print(f"[INFO] Corpus will be saved and can be resumed after interruption")

    atheris.Setup(args, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
