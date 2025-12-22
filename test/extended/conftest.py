"""
pytest configuration file for PDFMathTranslate tests

This file ensures that:
1. Test utilities can be imported correctly
2. Test paths are set up properly
3. Common fixtures are available to all tests
"""

import sys
import os
from pathlib import Path

# Add test directory to Python path for utils import
test_dir = Path(__file__).parent
if str(test_dir) not in sys.path:
    sys.path.insert(0, str(test_dir))

# Add project root to Python path
project_root = test_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
