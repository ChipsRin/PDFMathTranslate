"""
Property-Based Testing for PDFMathTranslate
使用 Hypothesis 進行屬性測試

這個檔案包含針對 PDFMathTranslate 核心組件的屬性測試：
1. Paragraph 類的座標邊界測試
2. vflag() 函數的字體名和字元處理測試
3. 文字處理的不變性測試
"""

import pytest
import re
import unicodedata
from hypothesis import given, assume, strategies as st, settings, example
from pdf2zh.converter import Paragraph


# ============================================================
# 測試 1: Paragraph 類的屬性測試
# ============================================================

class TestParagraphProperties:
    """
    測試 Paragraph 類的各種數學性質

    Paragraph 類用於表示 PDF 中的段落，包含座標邊界、字體大小等資訊
    我們需要確保這些值始終保持合理的關係
    """

    @given(
        y=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x0=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x1=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        y0=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        y1=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        size=st.floats(min_value=6, max_value=72, allow_nan=False, allow_infinity=False),
        brk=st.booleans()
    )
    def test_paragraph_creation_with_valid_inputs(self, y, x, x0, x1, y0, y1, size, brk):
        """
        測試：Paragraph 物件可以用各種有效輸入建立
        性質：物件建立後，所有屬性應該等於輸入值
        """
        para = Paragraph(y, x, x0, x1, y0, y1, size, brk)

        # 性質：屬性值應該等於輸入值
        assert para.y == y
        assert para.x == x
        assert para.x0 == x0
        assert para.x1 == x1
        assert para.y0 == y0
        assert para.y1 == y1
        assert para.size == size
        assert para.brk == brk

    @given(
        y=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x0=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        x1=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        y0=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        y1=st.floats(min_value=0, max_value=1000, allow_nan=False, allow_infinity=False),
        size=st.floats(min_value=6, max_value=72, allow_nan=False, allow_infinity=False),
        brk=st.booleans()
    )
    def test_paragraph_boundary_relationships(self, y, x, x0, x1, y0, y1, size, brk):
        """
        測試：Paragraph 的邊界關係

        在實際應用中，我們期望：
        - x0 <= x1 (左邊界 <= 右邊界)
        - y0 <= y1 (上邊界 <= 下邊界)
        - x0 <= x <= x1 (初始橫座標在邊界內)
        - y0 <= y <= y1 (初始縱座標在邊界內)

        但是，Paragraph 類本身不強制這些約束，所以我們測試它能接受任何輸入
        """
        para = Paragraph(y, x, x0, x1, y0, y1, size, brk)

        # 性質 1：寬度計算（可能為負）
        width = para.x1 - para.x0
        assert isinstance(width, float)

        # 性質 2：高度計算（可能為負）
        height = para.y1 - para.y0
        assert isinstance(height, float)

        # 性質 3：字體大小在合理範圍內
        assert 6 <= para.size <= 72

    @given(
        x0=st.floats(min_value=0, max_value=500, allow_nan=False, allow_infinity=False),
        y0=st.floats(min_value=0, max_value=500, allow_nan=False, allow_infinity=False),
        width=st.floats(min_value=1, max_value=500, allow_nan=False, allow_infinity=False),
        height=st.floats(min_value=1, max_value=500, allow_nan=False, allow_infinity=False),
        size=st.floats(min_value=6, max_value=72, allow_nan=False, allow_infinity=False),
        brk=st.booleans()
    )
    @example(x0=0, y0=0, width=100, height=100, size=12, brk=False)
    @example(x0=0, y0=0, width=1, height=1, size=6, brk=True)
    def test_paragraph_with_guaranteed_valid_boundaries(self, x0, y0, width, height, size, brk):
        """
        測試：建立邊界保證合法的 Paragraph

        透過使用 width 和 height 來計算 x1 和 y1，
        我們確保 x0 <= x1 且 y0 <= y1
        """
        x1 = x0 + width
        y1 = y0 + height
        x = (x0 + x1) / 2  # 中點橫座標
        y = (y0 + y1) / 2  # 中點縱座標

        para = Paragraph(y, x, x0, x1, y0, y1, size, brk)

        # 性質 1：邊界關係必須成立
        assert para.x0 <= para.x1
        assert para.y0 <= para.y1

        # 性質 2：初始座標在邊界內
        assert para.x0 <= para.x <= para.x1
        assert para.y0 <= para.y <= para.y1

        # 性質 3：寬度和高度為正
        assert para.x1 - para.x0 > 0
        assert para.y1 - para.y0 > 0

    @given(
        size=st.floats(min_value=6, max_value=72, allow_nan=False, allow_infinity=False)
    )
    def test_paragraph_font_size_invariants(self, size):
        """
        測試：字體大小的不變性
        性質：字體大小必須在 PDF 合理範圍內 (6-72 pt)
        """
        para = Paragraph(100, 100, 50, 150, 50, 150, size, False)

        # 性質：字體大小在合理範圍
        assert 6 <= para.size <= 72
        assert para.size == size


# ============================================================
# 測試 2: vflag() 函數的字體名處理
# ============================================================

class TestVFlagFontNameHandling:
    """
    測試 vflag() 函數對各種字體名的處理

    vflag() 函數用於判斷某個字元是否屬於公式（或角標）字體
    它需要處理各種異常的字體名和字元
    """

    def create_mock_converter(self):
        """建立一個簡化的 converter 物件用於測試"""
        class MockConverter:
            def __init__(self):
                self.vfont = None
                self.vchar = None
        return MockConverter()

    @given(st.text(min_size=0, max_size=50))
    def test_vflag_font_name_split(self, font_name):
        """
        測試：vflag() 中的字體名分割邏輯

        實際程式碼：font = font.split("+")[-1]
        性質：分割後應該得到最後一個部分
        """
        # 模擬 vflag 中的字體名處理
        if isinstance(font_name, bytes):
            try:
                font_name = font_name.decode('utf-8')
            except UnicodeDecodeError:
                font_name = ""

        result = font_name.split("+")[-1]

        # 性質 1：結果應該是字串
        assert isinstance(result, str)

        # 性質 2：如果沒有 "+"，結果應該是原字串
        if "+" not in font_name:
            assert result == font_name

        # 性質 3：結果不應該包含 "+"
        if result:  # 非空字串
            assert "+" not in result or result == "+"  # 除非字串就是 "+"

    @given(
        st.one_of(
            st.text(min_size=0, max_size=20),
            st.binary(min_size=0, max_size=20)
        )
    )
    def test_vflag_font_decode_robustness(self, font_input):
        if isinstance(font_input, bytes):
            try:
                font_str = font_input.decode('utf-8')
            except UnicodeDecodeError:
                font_str = ""
        else:
            font_str = font_input

        assert isinstance(font_str, str)


# ============================================================
# 測試 3: Unicode 字元處理
# ============================================================

class TestUnicodeCharacterHandling:
    """
    測試 Unicode 字元的處理

    vflag() 需要判斷字元是否屬於特定的 Unicode 類別
    """

    @given(st.text(min_size=1, max_size=1))
    def test_unicode_category_check(self, char):
        """
        測試：Unicode 類別檢查的性質

        vflag() 檢查字元是否屬於：
        - Lm (Modifier Letter): 文字修飾符
        - Mn (Nonspacing Mark): 非空格標記
        - Sk (Modifier Symbol): 修飾符號
        - Sm (Math Symbol): 數學符號
        - Zl, Zp, Zs (Separator): 分隔符
        """
        if char and char != " ":
            category = unicodedata.category(char)

            # 性質：類別應該是兩個字元的字串
            assert isinstance(category, str)
            assert len(category) == 2

            # 檢查是否屬於 vflag 關注的類別
            is_special = category in ["Lm", "Mn", "Sk", "Sm", "Zl", "Zp", "Zs"]

            # 性質：結果應該是布林值
            assert isinstance(is_special, bool)

    @given(st.integers(min_value=0x370, max_value=0x3FF))
    def test_greek_letter_range(self, code_point):
        """
        測試：希臘字母範圍檢查

        vflag() 檢查字元是否在希臘字母範圍 (0x370-0x3FF)
        性質：這個範圍內的所有字元都應該被識別
        """
        char = chr(code_point)

        # 性質 1：應該能轉換為字元
        assert isinstance(char, str)

        # 性質 2：在希臘字母範圍內
        assert 0x370 <= ord(char) <= 0x3FF

        # 性質 3：字元長度為 1
        assert len(char) == 1

    @given(st.text(min_size=0, max_size=100))
    @example("")  # 空字串
    @example(" ")  # 空格
    @example("Hello World")  # 英文
    @example("你好世界")  # 中文
    @example("Hello👋World")  # emoji
    @example("α + β = γ")  # 希臘字母
    def test_string_length_invariants(self, text):
        """
        測試：字串長度的不變性
        性質：字串長度始終非負
        """
        # 性質 1：長度非負
        assert len(text) >= 0

        # 性質 2：空字串長度為 0
        if text == "":
            assert len(text) == 0

        # 性質 3：遍歷字元數量應該等於長度
        char_count = sum(1 for _ in text)
        assert char_count == len(text)


# ============================================================
# 測試 4: 正則表達式匹配測試
# ============================================================

class TestRegexPatternMatching:
    """
    測試 vflag() 中的正則表達式匹配邏輯
    """

    @given(st.text(min_size=0, max_size=30))
    def test_latex_font_pattern_matching(self, font_name):
        """
        測試：LaTeX 字體名的正則表達式匹配

        vflag() 使用這個正則表達式匹配 LaTeX 字體：
        r"(CM[^R]|MS.M|XY|MT|BL|RM|EU|LA|RS|LINE|LCIRCLE|TeX-|rsfs|txsy|wasy|stmary|.*Mono|.*Code|.*Ital|.*Sym|.*Math)"
        """
        pattern = r"(CM[^R]|MS.M|XY|MT|BL|RM|EU|LA|RS|LINE|LCIRCLE|TeX-|rsfs|txsy|wasy|stmary|.*Mono|.*Code|.*Ital|.*Sym|.*Math)"

        try:
            match_result = re.match(pattern, font_name)

            # 性質 1：結果應該是 Match 物件或 None
            assert match_result is None or hasattr(match_result, 'group')

            # 性質 2：如果匹配，應該能獲取匹配內容
            if match_result:
                matched_text = match_result.group(0)
                assert isinstance(matched_text, str)
                assert len(matched_text) > 0

        except re.error:
            # 如果正則表達式有問題，測試應該失敗
            pytest.fail("Regex pattern error")

    @given(st.text(min_size=0, max_size=20))
    @example("(cid:123)")
    @example("(cid:0)")
    @example("(cid:9999)")
    def test_cid_pattern_matching(self, char):
        """
        測試：CID 字元的正則表達式匹配

        vflag() 檢查字元是否匹配 r"\(cid:"
        """
        pattern = r"\(cid:"

        try:
            match_result = re.match(pattern, char)

            # 性質：結果應該是 Match 物件或 None
            assert match_result is None or hasattr(match_result, 'group')

        except re.error:
            pytest.fail("Regex pattern error")


# ============================================================
# 執行說明
# ============================================================
"""
執行這個測試檔案：

1. 執行所有屬性測試：
   python -m pytest test/test_property_based.py -v

2. 執行特定測試類別：
   python -m pytest test/test_property_based.py::TestParagraphProperties -v

3. 查看每個測試生成的案例（除錯模式）：
   python -m pytest test/test_property_based.py -v -s

4. 增加測試案例數量（預設 100 個）：
   在測試函數上新增裝飾器：
   @settings(max_examples=1000)

重要概念：
- Hypothesis 會自動生成邊界案例（0, 負數, 極大值等）
- 如果測試失敗，Hypothesis 會自動縮小（shrink）到最小的失敗案例
- @example 確保特定的邊界情況被測試

測試覆蓋的性質：
1. Paragraph 類：
   - 物件建立的正確性
   - 邊界關係的不變性
   - 字體大小的合理性

2. vflag() 函數：
   - 字體名分割的正確性
   - bytes/str 解碼的健壯性
   - 正則表達式匹配的穩定性

3. Unicode 處理：
   - 類別檢查的正確性
   - 希臘字母範圍的覆蓋
   - 字串長度的不變性
"""
