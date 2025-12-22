"""
Input Space Partitioning (ISP) 系統化測試

這個測試展示如何使用 ISP 方法系統化地測試 PDF 翻譯：
1. 將任意 PDF 分類到 6 個維度的分區中
2. 根據分區特性驗證相應的屬性
3. 發現屬性違反，定位問題

設計原則：
- ISP 維度基於 PDF 格式和翻譯需求的通用分析（非針對特定檔案）
- 屬性測試關注端到端的翻譯品質（非底層實作細節）
"""

import pytest
import fitz  # PyMuPDF
from pathlib import Path
from typing import Dict, Tuple, List
from dataclasses import dataclass


@dataclass
class PDFCharacteristics:
    """PDF 的維度特徵"""
    pdf_version: str
    font_size_category: str
    font_type_category: str
    image_density: str
    page_count_category: str
    content_complexity: str

    # 原始數據
    min_font_size: float
    max_font_size: float
    avg_font_size: float
    total_chars: int
    total_images: int
    page_count: int
    has_math_fonts: bool


class ISPDimensionClassifier:
    """ISP 維度分類器 - 基於 PDF 格式通用特性設計"""

    @staticmethod
    def classify_pdf_version(pdf_path: str) -> str:
        """
        維度 1: PDF 版本
        設計理由: 不同版本有不同的壓縮算法、加密方式
        """
        doc = fitz.open(pdf_path)
        version = doc.metadata.get("format", "PDF-1.4")
        doc.close()

        if "1.1" in version or "1.2" in version or "1.3" in version:
            return "早期版本 (≤1.3)"
        elif "1.4" in version or "1.5" in version or "1.6" in version:
            return "中期版本 (1.4-1.6)"
        else:
            return "現代版本 (≥1.7)"

    @staticmethod
    def classify_font_size(pdf_path: str) -> Tuple[str, float, float, float]:
        """
        維度 2: 字體大小範圍
        設計理由: 極小字體用於浮水印/註釋，極大字體用於標題，
                 邊界處理可能不同
        """
        doc = fitz.open(pdf_path)
        font_sizes = []

        for page in doc:
            blocks = page.get_text("dict")["blocks"]
            for block in blocks:
                if block["type"] == 0:  # 文字區塊
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            size = span.get("size", 0)
                            if size > 0:
                                font_sizes.append(size)

        doc.close()

        if not font_sizes:
            return "無文字", 0, 0, 0

        min_size = min(font_sizes)
        max_size = max(font_sizes)
        avg_size = sum(font_sizes) / len(font_sizes)

        # 分類邏輯基於典型文檔字體使用
        if min_size < 1.0:
            category = "含極小字體 (<1.0pt)"
        elif max_size > 24.0:
            category = "含極大字體 (>24pt)"
        else:
            category = "標準字體範圍 (1-24pt)"

        return category, min_size, max_size, avg_size

    @staticmethod
    def classify_font_type(pdf_path: str) -> Tuple[str, bool]:
        """
        維度 3: 字體類型
        設計理由: Math fonts (CMM, CMSY) 需要特殊的 vflag 判斷
        """
        doc = fitz.open(pdf_path)
        font_names = set()

        for page in doc:
            blocks = page.get_text("dict")["blocks"]
            for block in blocks:
                if block["type"] == 0:
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            font = span.get("font", "")
                            if font:
                                font_names.add(font)

        doc.close()

        # 檢查是否有數學字體
        math_font_patterns = ["CMM", "CMSY", "CMEX", "CMMI", "rsfs", "txsy", "wasy", "stmary"]
        has_math = any(pattern in font for font in font_names for pattern in math_font_patterns)

        if has_math:
            return "含數學字體", True
        elif any("+" in font for font in font_names):  # Embedded fonts 有前綴
            return "含嵌入字體", False
        else:
            return "標準字體", False

    @staticmethod
    def classify_image_density(pdf_path: str) -> Tuple[str, int]:
        """
        維度 4: 圖片密度
        設計理由: 圖片影響記憶體使用和佈局重建
        """
        doc = fitz.open(pdf_path)
        total_images = 0

        for page in doc:
            images = page.get_images()
            total_images += len(images)

        page_count = len(doc)
        doc.close()

        if total_images == 0:
            return "無圖片", 0
        elif total_images / page_count < 2:
            return "稀疏圖片 (<2/頁)", total_images
        else:
            return "密集圖片 (≥2/頁)", total_images

    @staticmethod
    def classify_page_count(pdf_path: str) -> Tuple[str, int]:
        """
        維度 5: 頁面數量
        設計理由: 多頁處理需要正確的狀態管理
        """
        doc = fitz.open(pdf_path)
        count = len(doc)
        doc.close()

        if count == 1:
            return "單頁", count
        elif count <= 10:
            return "少量頁面 (2-10)", count
        else:
            return "大量頁面 (>10)", count

    @staticmethod
    def classify_content_complexity(pdf_path: str) -> str:
        """
        維度 6: 內容複雜度
        設計理由: 不同內容使用不同解析器
        """
        doc = fitz.open(pdf_path)

        # 簡單啟發式：檢查文字密度和圖片
        total_text_len = 0
        total_images = 0
        page_count = len(doc)

        for page in doc:
            text = page.get_text()
            total_text_len += len(text)
            total_images += len(page.get_images())

        doc.close()

        text_per_page = total_text_len / max(1, page_count)

        if total_images == 0 and text_per_page > 1000:
            return "純文字"
        elif total_images > 0:
            return "圖文混排"
        else:
            return "其他"

    @classmethod
    def analyze_pdf(cls, pdf_path: str) -> PDFCharacteristics:
        """完整分析 PDF 的所有維度特徵"""
        pdf_version = cls.classify_pdf_version(pdf_path)
        font_size_cat, min_fs, max_fs, avg_fs = cls.classify_font_size(pdf_path)
        font_type_cat, has_math = cls.classify_font_type(pdf_path)
        image_cat, img_count = cls.classify_image_density(pdf_path)
        page_cat, pg_count = cls.classify_page_count(pdf_path)
        content_cat = cls.classify_content_complexity(pdf_path)

        # 計算總字符數
        doc = fitz.open(pdf_path)
        total_chars = sum(len(page.get_text()) for page in doc)
        doc.close()

        return PDFCharacteristics(
            pdf_version=pdf_version,
            font_size_category=font_size_cat,
            font_type_category=font_type_cat,
            image_density=image_cat,
            page_count_category=page_cat,
            content_complexity=content_cat,
            min_font_size=min_fs,
            max_font_size=max_fs,
            avg_font_size=avg_fs,
            total_chars=total_chars,
            total_images=img_count,
            page_count=pg_count,
            has_math_fonts=has_math
        )


class PropertyValidator:
    """屬性驗證器 - 針對不同分區驗證相應的屬性"""

    @staticmethod
    def validate_content_preservation(original_path: str, translated_path: str) -> Tuple[bool, str, dict]:
        """
        屬性: 內容完整性
        適用分區: 所有
        期望: 翻譯後文字量應在合理範圍內
        """
        if not Path(translated_path).exists():
            return False, "翻譯文件不存在，無法驗證", {}

        # 提取文字和行數
        doc_orig = fitz.open(original_path)
        doc_trans = fitz.open(translated_path)

        orig_chars = sum(len(page.get_text("text")) for page in doc_orig)
        trans_chars = sum(len(page.get_text("text")) for page in doc_trans)
        
        orig_lines = sum(len(page.get_text("blocks")) for page in doc_orig)
        trans_lines = sum(len(page.get_text("blocks")) for page in doc_trans)

        doc_orig.close()
        doc_trans.close()

        if orig_chars == 0 and orig_lines == 0:
            return True, "原始文件無文字，跳過", {"original_chars": 0, "original_lines": 0}

        char_ratio = trans_chars / orig_chars if orig_chars > 0 else 0
        line_ratio = trans_lines / orig_lines if orig_lines > 0 else 0

        details = {
            "original_chars": orig_chars,
            "translated_chars": trans_chars,
            "char_ratio": char_ratio,
            "original_lines": orig_lines,
            "translated_lines": trans_lines,
            "line_ratio": line_ratio,
        }

        # 行數更能反映結構，設定較嚴格的閾值
        if line_ratio < 0.8:
            loss_rate = (1 - line_ratio) * 100
            return False, f"行數嚴重丟失 (損失 {loss_rate:.1f}%)", details
        
        # 字符數因語言轉換差異較大，設定較寬鬆的閾值
        if char_ratio < 0.3:
            loss_rate = (1 - char_ratio) * 100
            return False, f"字符數嚴重丟失 (損失 {loss_rate:.1f}%)", details

        if char_ratio > 5.0:
            increase_rate = (char_ratio - 1) * 100
            return False, f"字符數異常增加 (增加 {increase_rate:.1f}%)", details
        
        return True, f"內容完整性正常 (行數比例 {line_ratio:.2f}, 字符比例 {char_ratio:.2f})", details

    @staticmethod
    def validate_structure_preservation(original_path: str, translated_path: str) -> Tuple[bool, str, dict]:
        """
        屬性: 結構完整性
        適用分區: 所有
        期望: 頁面數應保持不變
        """
        if not Path(translated_path).exists():
            return False, "翻譯文件不存在，無法驗證", {}

        doc_orig = fitz.open(original_path)
        doc_trans = fitz.open(translated_path)

        orig_pages = len(doc_orig)
        trans_pages = len(doc_trans)

        doc_orig.close()
        doc_trans.close()

        details = {
            "original_pages": orig_pages,
            "translated_pages": trans_pages
        }

        if orig_pages == trans_pages:
            return True, f"結構完整性正常 ({orig_pages} 頁)", details
        else:
            return False, f"頁面數改變 ({orig_pages} → {trans_pages})", details


class TestISPSystematic:
    """ISP 系統化測試"""

    def test_analyze_pdf_characteristics(self):
        """
        步驟 1: 分析 PDF 的維度特徵

        這個測試展示如何將任意 PDF 分類到 ISP 的各個維度分區
        """
        # 測試文件
        test_files = [
            "test/fixtures/sample_pdfs/icml01-ffq_raw.pdf",
            "test/fixtures/sample_pdfs/1706.03762v7.pdf",
            "test/fixtures/sample_pdfs/2406.09676v2.pdf",
        ]

        print("\n" + "="*80)
        print("步驟 1: ISP 維度分析")
        print("="*80)

        for filepath in test_files:
            if not Path(filepath).exists():
                print(f"\n⚠️  文件不存在: {filepath}")
                continue

            print(f"\n📄 分析文件: {Path(filepath).name}")
            print("-" * 80)

            chars = ISPDimensionClassifier.analyze_pdf(filepath)

            print(f"維度 1 - PDF 版本:      {chars.pdf_version}")
            print(f"維度 2 - 字體大小:      {chars.font_size_category}")
            print(f"         └─ 範圍:       {chars.min_font_size:.2f} - {chars.max_font_size:.2f} pt (平均 {chars.avg_font_size:.2f})")
            print(f"維度 3 - 字體類型:      {chars.font_type_category}")
            print(f"維度 4 - 圖片密度:      {chars.image_density}")
            print(f"         └─ 總數:       {chars.total_images} 個")
            print(f"維度 5 - 頁面數量:      {chars.page_count_category}")
            print(f"         └─ 總數:       {chars.page_count} 頁")
            print(f"維度 6 - 內容複雜度:    {chars.content_complexity}")
            print(f"         └─ 總字符:     {chars.total_chars:,}")

            # 識別高風險分區
            risk_factors = []
            if "極小字體" in chars.font_size_category:
                risk_factors.append("⚠️  極小字體可能導致佈局計算問題")
            if "極大字體" in chars.font_size_category:
                risk_factors.append("⚠️  極大字體可能導致座標溢出")
            if chars.has_math_fonts:
                risk_factors.append("ℹ️  含數學字體，需要 vflag 判斷")
            if chars.total_images > 20:
                risk_factors.append("⚠️  大量圖片可能影響記憶體")

            if risk_factors:
                print("\n🔍 潛在風險因素:")
                for factor in risk_factors:
                    print(f"   {factor}")

    def test_validate_partition_properties(self):
        """
        步驟 2: 驗證各分區的屬性

        這個測試展示如何針對不同分區驗證相應的翻譯屬性
        """
        test_cases = [
            ("test/fixtures/sample_pdfs/icml01-ffq_raw.pdf", "test/fixtures/translated_pdfs/icml01-ffq_raw-mono.pdf"),
            ("test/fixtures/sample_pdfs/1706.03762v7.pdf", "test/fixtures/translated_pdfs/1706.03762v7-mono.pdf"),
            ("test/fixtures/sample_pdfs/2406.09676v2.pdf", "test/fixtures/translated_pdfs/2406.09676v2-mono.pdf"),
        ]

        print("\n" + "="*80)
        print("步驟 2: 屬性驗證")
        print("="*80)

        violations = []

        for original, translated in test_cases:
            # 1. Check if original file exists
            if not Path(original).exists():
                print(f"\n⚠️  原始文件不存在: {original}")
                continue

            # 2. Check if translated file already exists
            if Path(translated).exists():
                print(f"\n✅ 翻譯文件已存在，跳過翻譯: {Path(translated).name}")
            else:
                # Run the translation via CLI
                print(f"\n🔄 開始翻譯: {Path(original).name}")
                try:
                    import subprocess
                    output_dir = Path(translated).parent
                    output_dir.mkdir(parents=True, exist_ok=True)

                    command = [
                        "python", "-m", "pdf2zh.pdf2zh",
                        str(original),
                        "--service", "google",
                        "--lang-in", "en",
                        "--lang-out", "zh",
                        "--output", str(output_dir),
                        "--thread", "1",
                        "--ignore-cache"
                    ]

                    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
                    print(f"✅ 翻譯完成: {Path(translated).name}")

                except subprocess.CalledProcessError as e:
                    pytest.fail(f"翻譯過程失敗 for {original}. Error: {e.stderr}")
                except subprocess.TimeoutExpired:
                    pytest.fail(f"翻譯過程超時 for {original}")
                except Exception as e:
                    pytest.fail(f"執行 CLI 時發生未知錯誤 for {original}: {e}")

            # 3. Verify translated file exists before validation
            if not Path(translated).exists():
                pytest.fail(f"翻譯文件不存在: {translated}")

            # 2. Now, validate the properties
            print(f"\n📄 測試文件: {Path(original).name}")
            print("-" * 80)

            # 先分析維度
            chars = ISPDimensionClassifier.analyze_pdf(original)
            print(f"ISP 分區: {chars.font_size_category} / {chars.font_type_category} / {chars.content_complexity}")

            # 驗證屬性 1: 結構完整性
            print("\n🔍 驗證屬性 1: 結構完整性")
            success, msg, details = PropertyValidator.validate_structure_preservation(original, translated)
            print(f"   {'✅' if success else '❌'} {msg}")
            if details:
                print(f"      詳細: {details}")
            if not success:
                violations.append((Path(original).name, "結構完整性", msg, details))

            # 驗證屬性 2: 內容完整性
            print("\n🔍 驗證屬性 2: 內容完整性")
            success, msg, details = PropertyValidator.validate_content_preservation(original, translated)
            print(f"   {'✅' if success else '❌'} {msg}")
            if details:
                print(f"      原始字符: {details.get('original_chars', 0):,}")
                print(f"      翻譯字符: {details.get('translated_chars', 0):,}")
                if 'line_ratio' in details:
                    print(f"      行數比例: {details['line_ratio']:.2f}")
                if 'char_ratio' in details:
                    print(f"      字符比例: {details['char_ratio']:.2f}")

        # 總結
        print("\n" + "="*80)
        print("步驟 3: 問題定位")
        print("="*80)

        if violations:
            print(f"\n❌ 發現 {len(violations)} 個屬性違反:\n")
            for filename, prop, msg, details in violations:
                print(f"📌 文件: {filename}")
                print(f"   屬性: {prop}")
                print(f"   問題: {msg}")

                # 重新分析維度，找出可能的原因
                original_path = f"test/fixtures/sample_pdfs/{filename}"
                if Path(original_path).exists():
                    chars = ISPDimensionClassifier.analyze_pdf(original_path)
                    print(f"   ISP 分區: {chars.font_size_category}")

                    # 推斷可能原因
                    if "內容完整性" in prop and "極小字體" in chars.font_size_category:
                        print(f"   💡 可能原因: 極小字體 (min={chars.min_font_size:.2f}pt) 導致佈局處理異常")
                        print(f"      建議檢查: converter.py 中的字體大小過濾邏輯")

                print()
        else:
            print("\n✅ 所有測試通過，未發現屬性違反")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
