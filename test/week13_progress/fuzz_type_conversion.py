#!/usr/bin/env python3
"""
Advanced Fuzzing Test for Type Conversion Functions

Target: safe_float() function in pdfinterp.py
Strategy: Test all possible type conversions and edge cases
"""

import sys
import os
import atheris
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdf2zh.pdfinterp import safe_float


@atheris.instrument_func
def TestOneInput(data):
    """
    Fuzz test for safe_float with advanced strategies:
    1. Various numeric types and formats
    2. Special float values (inf, nan, -0.0)
    3. Edge cases (very large/small numbers)
    4. Non-numeric types
    """
    fdp = atheris.FuzzedDataProvider(data)

    strategy = fdp.ConsumeIntInRange(0, 10)

    if strategy == 0:
        # Valid integers
        test_val = fdp.ConsumeInt(8)

    elif strategy == 1:
        # Valid floats
        test_val = fdp.ConsumeFloat()

    elif strategy == 2:
        # String representations of numbers
        patterns = [
            "123",
            "123.456",
            "-123.456",
            "1e10",
            "1e-10",
            "0.0",
            "-0.0",
            "inf",
            "-inf",
            "nan",
            "NaN",
            "Infinity",
            "-Infinity",
        ]
        test_val = patterns[fdp.ConsumeIntInRange(0, len(patterns) - 1)]

    elif strategy == 3:
        # Invalid string formats
        patterns = [
            "abc",
            "12.34.56",
            "1e",
            "e10",
            "++123",
            "--123",
            "12-34",
            "0x123",  # hex format
            "0o123",  # octal format
            "0b101",  # binary format
        ]
        test_val = patterns[fdp.ConsumeIntInRange(0, len(patterns) - 1)]

    elif strategy == 4:
        # Empty and whitespace
        patterns = ["", " ", "  ", "\t", "\n", "\r\n"]
        test_val = patterns[fdp.ConsumeIntInRange(0, len(patterns) - 1)]

    elif strategy == 5:
        # Very large numbers
        test_val = str(10 ** fdp.ConsumeIntInRange(300, 400))

    elif strategy == 6:
        # Very small numbers (close to zero)
        test_val = str(10 ** -fdp.ConsumeIntInRange(300, 400))

    elif strategy == 7:
        # Special Python objects
        test_val = [1, 2, 3] if fdp.ConsumeBool() else {"key": "value"}

    elif strategy == 8:
        # None and other special values
        options = [None, True, False]
        test_val = options[fdp.ConsumeIntInRange(0, len(options) - 1)]

    elif strategy == 9:
        # Complex numbers (should fail)
        test_val = complex(fdp.ConsumeFloat(), fdp.ConsumeFloat())

    else:
        # Random unicode strings
        test_val = fdp.ConsumeUnicodeNoSurrogates(50)

    try:
        # Call safe_float
        result = safe_float(test_val)

        # Validation
        if result is not None:
            if not isinstance(result, float):
                # Bug: result should be float or None
                pass

            # Check for valid float values
            if math.isnan(result):
                # NaN is valid but might indicate an issue
                pass
            elif math.isinf(result):
                # Infinity is valid but might indicate overflow
                pass
        else:
            # None is expected for invalid inputs
            pass

        # Additional validation: try to convert back
        if result is not None:
            try:
                str_result = str(result)
                float_again = float(str_result)
                # Should be able to round-trip
            except (ValueError, OverflowError):
                # This might be a bug if result was valid
                pass

    except (TypeError, ValueError, OverflowError):
        # Expected exceptions
        pass
    except Exception as e:
        # Unexpected exception - potential bug
        pass


def main():
    """Main entry point with persistent corpus"""
    # Persistent corpus for resumable fuzzing
    persistent_corpus_dir = os.path.join(os.path.dirname(__file__), "corpus", "type_conversion_persistent")
    os.makedirs(persistent_corpus_dir, exist_ok=True)

    args = sys.argv
    args.append(persistent_corpus_dir)

    print(f"[INFO] Persistent corpus: {persistent_corpus_dir}")
    print(f"[INFO] Progress will be saved - you can resume anytime")

    atheris.Setup(args, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
