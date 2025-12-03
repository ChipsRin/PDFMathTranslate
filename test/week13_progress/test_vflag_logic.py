"""
vflag() 函數的邏輯正確性測試

Property-Based Testing 主要測試「健壯性」（不崩潰）
這個檔案測試「邏輯正確性」（是否正確判斷公式字元）

測試重點：
1. LaTeX 數學字體應該被正確識別
2. 一般字體不應該被誤判
3. 數學符號應該被正確識別
4. 希臘字母應該被正確識別
5. 一般文字不應該被誤判
"""

import pytest
import re
import unicodedata
from hypothesis import given, strategies as st, example


# ============================================================
# 模擬 vflag() 函數（因為它在 converter 類內部）
# ============================================================

def vflag_standalone(font: str, char: str, vfont=None, vchar=None):
    """
    獨立的 vflag() 函數，用於測試
    複製自 pdf2zh/converter.py:190-224
    """
    # 處理 bytes
    if isinstance(font, bytes):
        try:
            font = font.decode('utf-8')
        except UnicodeDecodeError:
            font = ""

    # 字體名截斷
    font = font.split("+")[-1]

    # 檢查 CID
    if re.match(r"\(cid:", char):
        return True

    # 基於字體名規則的判定
    if vfont:
        if re.match(vfont, font):
            return True
    else:
        if re.match(
            r"(CM[^R]|MS.M|XY|MT|BL|RM|EU|LA|RS|LINE|LCIRCLE|TeX-|rsfs|txsy|wasy|stmary|.*Mono|.*Code|.*Ital|.*Sym|.*Math)",
            font,
        ):
            return True

    # 基於字符集規則的判定
    if vchar:
        if re.match(vchar, char):
            return True
    else:
        if (
            char
            and char != " "
            and (
                unicodedata.category(char[0])
                in ["Lm", "Mn", "Sk", "Sm", "Zl", "Zp", "Zs"]
                or ord(char[0]) in range(0x370, 0x400)  # 希臘字母
            )
        ):
            return True

    return False


# ============================================================
# 測試 1: LaTeX 數學字體識別的正確性
# ============================================================

class TestLatexMathFontRecognition:
    """
    測試 vflag() 是否正確識別 LaTeX 數學字體

    這是**邏輯正確性測試**，不是健壯性測試
    """

    def test_cmm_fonts_should_be_recognized(self):
        """
        測試：CM 系列數學字體應該被識別為公式

        CMM = Computer Modern Math（數學字體）
        CMR = Computer Modern Roman（一般字體）
        """
        # 應該被識別為數學字體
        assert vflag_standalone("CMM10", "a") == True, "CMM10 是數學字體，應該回傳 True"
        assert vflag_standalone("CMMI10", "a") == True, "CMMI10 是數學字體，應該回傳 True"
        assert vflag_standalone("CMSY10", "a") == True, "CMSY10 是數學字體，應該回傳 True"
        assert vflag_standalone("CMEX10", "a") == True, "CMEX10 是數學字體，應該回傳 True"

        # 不應該被識別為數學字體
        assert vflag_standalone("CMR10", "a") == False, "CMR10 是一般字體，應該回傳 False"
        assert vflag_standalone("CMRR10", "a") == False, "CMRR10 以 R 開頭，應該回傳 False"

    def test_latex_symbol_fonts(self):
        """
        測試：LaTeX 符號字體應該被識別
        """
        latex_fonts = [
            "rsfs10",      # Ralph Smith Formal Script
            "txsy10",      # TX Symbol
            "wasy10",      # Waldi Symbol
            "stmary10",    # St Mary Road
            "TeX-Math",    # TeX Math
        ]

        for font in latex_fonts:
            result = vflag_standalone(font, "a")
            assert result == True, f"{font} 是數學字體，但被誤判為 False"

    def test_mono_code_italic_fonts(self):
        """
        測試：包含特定關鍵字的字體應該被識別

        關鍵字：Mono, Code, Ital, Sym, Math
        """
        special_fonts = [
            "CourierMono",      # 包含 Mono
            "SourceCode",       # 包含 Code
            "Times-Italic",     # 包含 Ital
            "Symbol",           # 包含 Sym
            "ArialMath",        # 包含 Math
        ]

        for font in special_fonts:
            result = vflag_standalone(font, "a")
            assert result == True, f"{font} 應該被識別為數學字體"

    def test_normal_fonts_should_not_be_recognized(self):
        """
        測試：一般字體不應該被誤判為數學字體
        """
        normal_fonts = [
            "Arial",
            "Times-Roman",
            "Helvetica",
            "Verdana",
            "Georgia",
        ]

        for font in normal_fonts:
            # 使用一般字元 'a'，不應該觸發字體規則
            result = vflag_standalone(font, "a")
            assert result == False, f"{font} 是一般字體，不應該被識別為數學字體"

    def test_font_name_with_prefix(self):
        """
        測試：帶前綴的字體名稱應該被正確處理

        PDF 中的字體名稱格式：ABCDEE+FontName
        vflag() 會分割並取最後一部分
        """
        # 帶前綴的數學字體
        assert vflag_standalone("ABCDEE+CMM10", "a") == True
        assert vflag_standalone("XYZABC+rsfs10", "a") == True

        # 帶前綴的一般字體
        assert vflag_standalone("ABCDEE+Arial", "a") == False


# ============================================================
# 測試 2: 數學符號識別的正確性
# ============================================================

class TestMathSymbolRecognition:
    """
    測試 vflag() 是否正確識別數學符號
    """

    def test_common_math_symbols(self):
        """
        測試：常見的數學符號應該被識別

        這些符號的 Unicode 類別是 Sm (Math Symbol)
        """
        math_symbols = [
            "+",   # PLUS SIGN
            "-",   # MINUS SIGN
            "×",   # MULTIPLICATION SIGN
            "÷",   # DIVISION SIGN
            "=",   # EQUALS SIGN
            "≠",   # NOT EQUAL TO
            "≤",   # LESS-THAN OR EQUAL TO
            "≥",   # GREATER-THAN OR EQUAL TO
            "∑",   # SUMMATION
            "∫",   # INTEGRAL
            "∞",   # INFINITY
            "√",   # SQUARE ROOT
        ]

        for symbol in math_symbols:
            # 使用一般字體（如 Arial），但符號本身應該被識別
            result = vflag_standalone("Arial", symbol)
            category = unicodedata.category(symbol)
            assert result == True, f"{symbol} (類別:{category}) 是數學符號，應該被識別"

    def test_greek_letters(self):
        """
        測試：希臘字母應該被識別為公式字元

        希臘字母範圍：0x370-0x3FF
        常用於數學公式
        """
        greek_letters = [
            ("α", 0x3B1, "alpha"),
            ("β", 0x3B2, "beta"),
            ("γ", 0x3B3, "gamma"),
            ("δ", 0x3B4, "delta"),
            ("π", 0x3C0, "pi"),
            ("θ", 0x3B8, "theta"),
            ("λ", 0x3BB, "lambda"),
            ("μ", 0x3BC, "mu"),
            ("σ", 0x3C3, "sigma"),
            ("Σ", 0x3A3, "Sigma"),
        ]

        for char, code, name in greek_letters:
            result = vflag_standalone("Arial", char)
            assert result == True, f"{char} ({name}, U+{code:04X}) 是希臘字母，應該被識別"
            assert ord(char) in range(0x370, 0x400), f"{char} 不在希臘字母範圍內"

    def test_normal_latin_letters(self):
        """
        測試：一般的拉丁字母不應該被誤判
        """
        normal_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

        for char in normal_chars:
            # 使用一般字體，一般字元不應該被識別為公式
            result = vflag_standalone("Arial", char)
            assert result == False, f"{char} 是一般字母，不應該被識別為公式"

    def test_space_should_not_be_recognized(self):
        """
        測試：空格不應該被識別為公式

        vflag() 中有特別檢查 char != " "
        """
        result = vflag_standalone("Arial", " ")
        assert result == False, "空格不應該被識別為公式"


# ============================================================
# 測試 3: CID 字元識別
# ============================================================

class TestCIDRecognition:
    """
    測試 vflag() 對 CID 字元的識別

    CID = Character ID，PDF 內部的字元編碼
    """

    def test_cid_pattern_should_be_recognized(self):
        """
        測試：CID 格式的字元應該被識別為公式

        格式：(cid:數字)
        """
        cid_chars = [
            "(cid:0)",
            "(cid:123)",
            "(cid:9999)",
            "(cid:1234567)",
        ]

        for char in cid_chars:
            result = vflag_standalone("Arial", char)
            assert result == True, f"{char} 是 CID 格式，應該被識別為公式"

    def test_non_cid_should_not_match(self):
        """
        測試：不是 CID 格式的不應該被誤判
        """
        non_cid = [
            "cid:123",      # 沒有括號
            "(cid)",        # 沒有冒號和數字
            "(123)",        # 沒有 cid:
            "abc",          # 一般字元
        ]

        for char in non_cid:
            # 這些不會被 CID 規則識別，但可能被其他規則識別
            # 這裡只測試 CID 規則不會誤判
            if re.match(r"\(cid:", char):
                assert False, f"{char} 不應該匹配 CID 模式"


# ============================================================
# 測試 4: 邊界案例和組合測試
# ============================================================

class TestEdgeCasesAndCombinations:
    """
    測試邊界案例和多個規則的組合
    """

    def test_math_font_with_math_symbol(self):
        """
        測試：數學字體 + 數學符號 → 應該被識別
        """
        result = vflag_standalone("CMM10", "+")
        assert result == True, "數學字體 + 數學符號應該被識別"

    def test_math_font_with_normal_char(self):
        """
        測試：數學字體 + 一般字元 → 應該被識別（因為字體）
        """
        result = vflag_standalone("CMM10", "a")
        assert result == True, "數學字體即使是一般字元也應該被識別"

    def test_normal_font_with_math_symbol(self):
        """
        測試：一般字體 + 數學符號 → 應該被識別（因為符號）
        """
        result = vflag_standalone("Arial", "+")
        assert result == True, "一般字體但有數學符號應該被識別"

    def test_normal_font_with_normal_char(self):
        """
        測試：一般字體 + 一般字元 → 不應該被識別
        """
        result = vflag_standalone("Arial", "a")
        assert result == False, "一般字體 + 一般字元不應該被識別"

    def test_empty_font_name(self):
        """
        測試：空字體名稱的處理
        """
        # 空字體名稱，一般字元
        result = vflag_standalone("", "a")
        assert result == False, "空字體名稱 + 一般字元不應該被識別"

        # 空字體名稱，數學符號
        result = vflag_standalone("", "+")
        assert result == True, "空字體名稱但有數學符號應該被識別"

    def test_empty_char(self):
        """
        測試：空字元的處理
        """
        result = vflag_standalone("CMM10", "")
        assert result == False, "空字元不應該被識別（即使是數學字體）"


# ============================================================
# 測試 5: 使用 Hypothesis 發現潛在錯誤
# ============================================================

class TestPotentialBugsWithHypothesis:
    """
    使用 Hypothesis 的進階功能來發現潛在的邏輯錯誤
    """

    @given(
        font=st.text(min_size=0, max_size=50),
        char=st.text(min_size=0, max_size=1)
    )
    def test_vflag_return_type_is_always_boolean(self, font, char):
        """
        性質測試：vflag() 的回傳值必須永遠是布林值
        """
        result = vflag_standalone(font, char)
        assert isinstance(result, bool), f"vflag() 必須回傳布林值，但回傳了 {type(result)}"

    @given(
        font=st.text(min_size=0, max_size=50),
        char=st.text(min_size=1, max_size=1)
    )
    @example(font="CMM10", char="a")
    @example(font="CMR10", char="a")
    @example(font="Arial", char="+")
    @example(font="Arial", char="α")
    def test_vflag_consistency(self, font, char):
        """
        性質測試：相同的輸入應該得到相同的輸出（一致性）
        """
        result1 = vflag_standalone(font, char)
        result2 = vflag_standalone(font, char)
        assert result1 == result2, "相同的輸入應該得到相同的輸出"

    @given(char=st.text(min_size=1, max_size=1))
    def test_math_font_always_returns_true(self, char):
        """
        性質測試：數學字體對任何字元都應該回傳 True
        """
        math_fonts = ["CMM10", "CMSY10", "rsfs10"]

        for font in math_fonts:
            result = vflag_standalone(font, char)
            # 除了空格以外，數學字體都應該回傳 True
            if char != " " and char != "":
                assert result == True, f"數學字體 {font} 對字元 {repr(char)} 應該回傳 True"


# ============================================================
# 執行說明
# ============================================================
"""
執行這個測試檔案：

1. 執行所有邏輯測試：
   python -m pytest test/test_vflag_logic.py -v

2. 執行特定測試類別：
   python -m pytest test/test_vflag_logic.py::TestLatexMathFontRecognition -v

3. 查看詳細輸出：
   python -m pytest test/test_vflag_logic.py -v -s

測試覆蓋：
- ✅ LaTeX 數學字體識別的正確性
- ✅ 數學符號識別的正確性
- ✅ 希臘字母識別的正確性
- ✅ 一般字元不被誤判
- ✅ CID 字元識別
- ✅ 邊界案例和組合測試

與 test_property_based.py 的差異：
- test_property_based.py：測試「健壯性」（不崩潰）
- test_vflag_logic.py：測試「邏輯正確性」（正確判斷）

兩者互補，共同確保程式的品質！
"""
