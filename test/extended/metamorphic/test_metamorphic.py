import unittest
import fitz  # PyMuPDF
from pathlib import Path
import numpy as np
from typing import List, Tuple
import logging

# 使用統一的 PDFAnalyzer 工具類
from utils.pdf_analyzer import PDFAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestMetamorphicRelations(unittest.TestCase):
    """Metamorphic Testing 測試套件"""

    @classmethod
    def setUpClass(cls):
        """設置測試環境"""
        cls.test_pdfs = {
            "icml01": {
                "original": "test/fixtures/sample_pdfs/icml01-ffq_raw.pdf",
                "translated": "test/fixtures/translated_pdfs/icml01-ffq_raw-mono.pdf",
            },
            "1706": {
                "original": "test/fixtures/sample_pdfs/1706.03762v7.pdf",
                "translated": "test/fixtures/translated_pdfs/1706.03762v7-mono.pdf",
            },
            "2406": {
                "original": "test/fixtures/sample_pdfs/2406.09676v2.pdf",
                "translated": "test/fixtures/translated_pdfs/2406.09676v2-mono.pdf",
            }
        }

        # 確認文件存在
        for name, paths in cls.test_pdfs.items():
            if not Path(paths["original"]).exists():
                logger.warning(f"{name} original PDF not found: {paths['original']}")
            if not Path(paths["translated"]).exists():
                logger.warning(f"{name} translated PDF not found: {paths['translated']}")

    def test_MR1_layout_preservation_icml01(self):
        """
        MR1: 版面保持性測試 - icml01

        Metamorphic Relation:
        ∀ PDF p: layout_similarity(translate(p), p) > threshold

        預期: icml01 會失敗（文字消失 + 公式翻轉）
        """
        logger.info("\n=== MR1: 版面保持性測試 (icml01) ===")

        original = self.test_pdfs["icml01"]["original"]
        translated = self.test_pdfs["icml01"]["translated"]

        if not Path(original).exists() or not Path(translated).exists():
            self.skipTest("PDF files not found")

        # 提取文字框
        orig_boxes = PDFAnalyzer.extract_text_boxes(original)
        trans_boxes = PDFAnalyzer.extract_text_boxes(translated)

        logger.info(f"原始 PDF: {len(orig_boxes)} 個文字框")
        logger.info(f"翻譯 PDF: {len(trans_boxes)} 個文字框")

        # 檢查文字框數量
        box_ratio = len(trans_boxes) / len(orig_boxes) if orig_boxes else 0
        logger.info(f"文字框保留率: {box_ratio*100:.1f}%")

        # MR1a: 至少保留 90% 的文字框
        self.assertGreater(box_ratio, 0.9,
                          f"文字框大量丟失: {len(orig_boxes)} → {len(trans_boxes)}")

        # MR1b: 文字框位置相似度
        similarity = PDFAnalyzer.compare_bbox_positions(orig_boxes, trans_boxes)
        logger.info(f"位置相似度: {similarity*100:.1f}%")

        self.assertGreater(similarity, 0.8,
                          f"文字框位置改變過大: 相似度 {similarity*100:.1f}%")

    def test_MR1_layout_preservation_1706(self):
        """
        MR1: 版面保持性測試 - 1706

        預期: 1706 應該通過（正常 PDF）
        """
        logger.info("\n=== MR1: 版面保持性測試 (1706) ===")

        original = self.test_pdfs["1706"]["original"]
        translated = self.test_pdfs["1706"]["translated"]

        if not Path(original).exists() or not Path(translated).exists():
            self.skipTest("PDF files not found")

        orig_boxes = PDFAnalyzer.extract_text_boxes(original)
        trans_boxes = PDFAnalyzer.extract_text_boxes(translated)

        logger.info(f"原始 PDF: {len(orig_boxes)} 個文字框")
        logger.info(f"翻譯 PDF: {len(trans_boxes)} 個文字框")

        box_ratio = len(trans_boxes) / len(orig_boxes) if orig_boxes else 0
        logger.info(f"文字框保留率: {box_ratio*100:.1f}%")

        # 正常 PDF 應該保留大部分文字框
        self.assertGreater(box_ratio, 0.9,
                          f"正常 PDF 翻譯後文字框丟失: {box_ratio*100:.1f}%")

    def test_MR2_text_amount_preservation(self):
        """
        MR2: 文字量保持性測試

        Metamorphic Relation:
        ∀ PDF p: 0.8 ≤ |translate(p)| / |p| ≤ 1.2

        預期: icml01 會失敗（87.2% 丟失）
        """
        logger.info("\n=== MR2: 文字量保持性測試 ===")

        for name, paths in self.test_pdfs.items():
            original = paths["original"]
            translated = paths["translated"]

            if not Path(original).exists() or not Path(translated).exists():
                logger.warning(f"Skipping {name}: files not found")
                continue

            logger.info(f"\n測試 {name}:")

            # 檢查字符數
            orig_chars = PDFAnalyzer.count_chars(original)
            trans_chars = PDFAnalyzer.count_chars(translated)

            logger.info(f"原始字符數: {orig_chars}")
            logger.info(f"翻譯字符數: {trans_chars}")

            # 檢查行數（更準確的指標）
            orig_lines = PDFAnalyzer.count_lines(original)
            trans_lines = PDFAnalyzer.count_lines(translated)

            logger.info(f"原始行數: {orig_lines}")
            logger.info(f"翻譯行數: {trans_lines}")

            if orig_chars > 0:
                char_ratio = trans_chars / orig_chars
                char_loss_rate = (1 - char_ratio) * 100
                logger.info(f"字符保留率: {char_ratio*100:.1f}%")
                logger.info(f"字符丟失率: {char_loss_rate:.1f}%")

            if orig_lines > 0:
                line_ratio = trans_lines / orig_lines
                line_loss_rate = (1 - line_ratio) * 100
                logger.info(f"行數保留率: {line_ratio*100:.1f}%")
                logger.info(f"行數丟失率: {line_loss_rate:.1f}%")

                # MR2: 文字量應該保持在 80%-120%
                # 同時檢查字符數和行數
                self.assertGreater(char_ratio, 0.8,
                                  f"{name}: 字符大量丟失 {char_loss_rate:.1f}%")
                self.assertGreater(line_ratio, 0.8,
                                  f"{name}: 行數大量丟失 {line_loss_rate:.1f}%")
                self.assertLess(char_ratio, 1.2,
                               f"{name}: 字符異常增加")
                self.assertLess(line_ratio, 1.2,
                               f"{name}: 行數異常增加")

    def test_MR3_orientation_consistency(self):
        """
        MR3: 方向一致性測試

        Metamorphic Relation:
        ∀ PDF p: orientation(translate(p)) == orientation(p)

        預期: icml01 第 3 頁會失敗（公式翻轉）
        """
        logger.info("\n=== MR3: 方向一致性測試 ===")

        # 測試 icml01 第 3 頁（有翻轉問題）
        original = self.test_pdfs["icml01"]["original"]
        translated = self.test_pdfs["icml01"]["translated"]

        if not Path(original).exists() or not Path(translated).exists():
            self.skipTest("PDF files not found")

        test_page = 2  # 第 3 頁（0-indexed）

        orig_dir = PDFAnalyzer.check_text_orientation(original, test_page)
        trans_dir = PDFAnalyzer.check_text_orientation(translated, test_page)

        logger.info(f"原始 PDF 方向: {orig_dir}")
        logger.info(f"翻譯 PDF 方向: {trans_dir}")

        # MR3: 不應該有翻轉的文字
        if trans_dir.get("flipped", 0) > 0:
            total = sum(trans_dir.values())
            flipped_ratio = trans_dir["flipped"] / total if total > 0 else 0
            logger.warning(f"⚠️ 發現翻轉文字: {flipped_ratio*100:.1f}%")

            self.assertLess(flipped_ratio, 0.1,
                           f"文字方向翻轉: {flipped_ratio*100:.1f}%")

    def test_MR4_cross_page_consistency(self):
        """
        MR4: 跨頁一致性

        Metamorphic Relation:
        如果所有頁面使用相同的字體，翻譯後也應該一致

        這可能發現只影響特定頁面的 bug
        """
        logger.info("\n=== MR4: 跨頁一致性測試 ===")

        for name, paths in self.test_pdfs.items():
            original = paths["original"]
            translated = paths["translated"]

            if not Path(original).exists() or not Path(translated).exists():
                logger.warning(f"Skipping {name}: files not found")
                continue

            logger.info(f"\n測試 {name}:")

            doc_orig = fitz.open(original)
            doc_trans = fitz.open(translated)

            page_count = min(len(doc_orig), len(doc_trans), 5)

            # 檢查每頁的行數變化是否一致
            loss_rates = []

            for i in range(page_count):
                orig_blocks = doc_orig[i].get_text("dict")["blocks"]
                trans_blocks = doc_trans[i].get_text("dict")["blocks"]

                orig_text_blocks = [b for b in orig_blocks if b["type"] == 0]
                trans_text_blocks = [b for b in trans_blocks if b["type"] == 0]

                if len(orig_text_blocks) > 0:
                    ratio = len(trans_text_blocks) / len(orig_text_blocks)
                    loss_rate = (1 - ratio) * 100
                    loss_rates.append(loss_rate)

                    logger.info(f"  第 {i+1} 頁: {len(orig_text_blocks)} → {len(trans_text_blocks)} blocks (丟失 {loss_rate:.1f}%)")

            doc_orig.close()
            doc_trans.close()

            # MR4: 不同頁面的丟失率應該相近
            if len(loss_rates) > 1:
                std = np.std(loss_rates)
                logger.info(f"  丟失率標準差: {std:.1f}%")

                if std > 20:
                    logger.warning(f"⚠️ 不同頁面的處理不一致（標準差 {std:.1f}%）")
                    # 找出異常的頁面
                    mean_loss = np.mean(loss_rates)
                    for i, loss in enumerate(loss_rates):
                        if abs(loss - mean_loss) > 30:
                            logger.warning(f"    第 {i+1} 頁異常: 丟失 {loss:.1f}% (平均 {mean_loss:.1f}%)")


if __name__ == "__main__":
    # 執行測試並顯示詳細輸出
    unittest.main(verbosity=2)
