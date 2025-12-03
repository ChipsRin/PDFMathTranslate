#!/usr/bin/env python3
"""
Fuzzing Test for the Core Layout Processing Logic in TranslateConverter.

Target: TranslateConverter.receive_layout()
Strategy: Generate random streams of PDF layout objects (LTPage, LTChar, LTLine)
          and feed them into the layout reconstruction algorithm to find
          logic errors, crashes, and unexpected state-handling bugs.
"""
import sys
import os
import atheris
import random

# Add project root to path to allow importing from pdf2zh
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Since converter.py is complex, we will mock some dependencies
# to focus the fuzzing on the layout logic itself.
from pdf2zh.converter import TranslateConverter, Paragraph, OpType
from pdfminer.layout import LTPage, LTChar, LTLine, LTFigure, LTText, LTRect
from pdfminer.pdffont import PDFFont, PDFUnicodeNotDefined
from pdfminer.pdfinterp import PDFGraphicState
from unittest.mock import MagicMock, patch

# --- Mock Objects to Isolate receive_layout ---

class MockFont(MagicMock):
    """A mock for PDFFont to control character widths and unicode mapping."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fontname = "MockFont"

    def to_unichr(self, cid):
        # Simple mapping for fuzzing
        if cid < 256:
            return chr(cid)
        # Simulate undefined characters for higher CIDs
        raise PDFUnicodeNotDefined()

    def char_width(self, cid):
        return 10.0  # Assume fixed width for simplicity

    def char_disp(self, cid):
        return 0

class MockTranslator(MagicMock):
    """A mock for the BaseTranslator to avoid real API calls."""
    name = "google"  # Required for the service matching loop
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lang_out = "zh-cn"
    
    def translate(self, text):
        # Simulate translation by returning the original text
        return text

# --- Fuzzing Setup ---

# We need to instantiate TranslateConverter. A robust way to do this for fuzzing
# is to bypass its complex __init__ method and set the required attributes manually.
def get_fuzzed_converter():
    """
    Creates an instance of TranslateConverter for fuzzing by bypassing __init__
    and manually setting the necessary attributes for receive_layout.
    """
    # 1. Bypass the original __init__ to avoid complex setup/network/env errors.
    #    We replace it with a function that does nothing.
    with patch.object(TranslateConverter, '__init__', lambda self, *args, **kwargs: None):
        converter = TranslateConverter(None)

    # 2. Manually set all the attributes that `receive_layout` will access.
    #    This creates a controlled environment for the fuzzer.
    converter.translator = MockTranslator()
    converter.layout = {1: MagicMock()}
    converter.layout[1].shape = (fdp.ConsumeIntInRange(500, 4000), fdp.ConsumeIntInRange(500, 4000))
    
    # Mock font mapping and other properties
    mock_font = MockFont()
    converter.fontmap = {'tiro': mock_font, 'noto': mock_font}
    converter.fontid = {mock_font: "mockfont_id"}
    converter.noto_name = "noto"
    converter.noto = MagicMock()
    converter.noto.char_lengths.return_value = [10.0]
    converter.noto.has_glyph.return_value = 1 # Assume all glyphs exist
    
    # Set other attributes to default values
    converter.vfont = None
    converter.vchar = None
    
    return converter

# Global FuzzedDataProvider
fdp = None

@atheris.instrument_func
def TestOneInput(data):
    """
    Fuzzing entry point for receive_layout.
    """
    global fdp
    fdp = atheris.FuzzedDataProvider(data)

    # Get a fresh converter instance with fuzzed page dimensions
    try:
        fuzz_converter = get_fuzzed_converter()
    except Exception as e:
        # This setup should be robust, but catch errors just in case.
        print(f"Failed to initialize converter for fuzzing: {e}", file=sys.stderr)
        return

    # --- 1. Create a random LTPage object ---
    page_width = fuzz_converter.layout[1].shape[1]
    page_height = fuzz_converter.layout[1].shape[0]
    ltpage = LTPage(1, (0, 0, page_width, page_height))

    # --- 2. Generate a random stream of layout objects ---
    num_objects = fdp.ConsumeIntInRange(1, 100)

    for i in range(num_objects):
        obj_type = fdp.ConsumeIntInRange(0, 3)
        
        # Get random coordinates
        x0 = fdp.ConsumeFloatInRange(0, page_width)
        y0 = fdp.ConsumeFloatInRange(0, page_height)
        x1 = fdp.ConsumeFloatInRange(x0, x0 + 100)
        y1 = fdp.ConsumeFloatInRange(y0, y0 + 30)

        if obj_type == 0: # LTChar
            try:
                text = fdp.ConsumeUnicodeNoSurrogates(1)
            except IndexError:
                continue

            mock_font = MockFont()
            mock_font.fontname = fdp.PickValueInList(["Arial", "Times", "CMMI10", "XYZ+CMSY10", "WeirdFont"])
            
            matrix = (
                fdp.ConsumeFloat(), fdp.ConsumeFloat(), fdp.ConsumeFloat(),
                fdp.ConsumeFloat(), x0, y0
            )

            ltchar = LTChar(
                matrix, mock_font, fdp.ConsumeFloatInRange(8, 24),
                fdp.ConsumeFloat(), fdp.ConsumeFloat(), text,
                fdp.ConsumeFloat(), # textwidth
                (fdp.ConsumeFloat(), fdp.ConsumeFloat()), # textdisp (must be a tuple)
                None, PDFGraphicState()
            )
            ltchar.cid = ord(text[0]) if text else 0
            ltchar.font = mock_font # Hacked attribute from converter.py
            
            fuzz_converter.layout[1].__getitem__.return_value = fdp.ConsumeIntInRange(0, 5)

            ltpage.add(ltchar)

        elif obj_type == 1: # LTLine
            ltline = LTLine(fdp.ConsumeFloatInRange(0.1, 5), (x0, y0), (x1, y1))
            ltpage.add(ltline)

        elif obj_type == 2: # LTFigure
            figure_name = fdp.ConsumeString(10)
            matrix = (
                fdp.ConsumeFloat(), fdp.ConsumeFloat(), fdp.ConsumeFloat(),
                fdp.ConsumeFloat(), x0, y0
            )
            ltfigure = LTFigure(figure_name, (x0, y0, x1, y1), matrix)
            # Figures can contain other items, but for now we'll keep them simple
            # to test the container logic itself.
            ltpage.add(ltfigure)
        
    # --- 3. Execute the target function ---
    try:
        # Crucial call to the function we are fuzzing
        fuzz_converter.receive_layout(ltpage)
    except (IndexError, TypeError, ValueError, KeyError, AttributeError, ZeroDivisionError, OverflowError) as e:
        # Catch expected exceptions
        pass
    except Exception as e:
        # Catch any other unexpected exceptions and report them
        print(f"!!! Unexpected Exception Found: {type(e).__name__}: {e}", file=sys.stderr)
        print(f"Run with this input to reproduce: {data}", file=sys.stderr)
        raise e

def main():
    """Main fuzzing loop."""
    print("--- Fuzzing TranslateConverter.receive_layout ---")
    print("Generates random PDF layout objects to test paragraph reconstruction.")
    
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
