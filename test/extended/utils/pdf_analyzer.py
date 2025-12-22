"""
統一的 PDF 分析工具類

整合了原本分散在 test_pdf_properties.py 和 test_metamorphic.py 中的 PDFAnalyzer 類，
提供完整的 PDF 分析功能，包括：
- 文字分析（字符數、行數）
- 字體分析（字體大小、極小字體檢測）
- 版面分析（文字框位置、文字密度）
- 方向分析（文字方向、翻轉檢測）
- 頁面屬性（頁數、圖片數）
"""

import fitz  # PyMuPDF
from typing import Dict, List, Tuple
import numpy as np


class PDFAnalyzer:
    """統一的 PDF 分析工具類"""

    # ==================== 文字分析 ====================

    @staticmethod
    def count_chars(pdf_path: str) -> int:
        """
        計算 PDF 中的字符總數（去除空白後）

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            int: 總字符數
        """
        doc = fitz.open(pdf_path)
        total_chars = 0
        for page in doc:
            text = page.get_text()
            total_chars += len(text.strip())
        doc.close()
        return total_chars

    @staticmethod
    def get_text_length(pdf_path: str) -> int:
        """
        獲取 PDF 總字符數（包含空白）

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            int: 總字符數
        """
        doc = fitz.open(pdf_path)
        total = sum(len(doc[i].get_text()) for i in range(len(doc)))
        doc.close()
        return total

    @staticmethod
    def count_lines(pdf_path: str) -> int:
        """
        計算 PDF 中的文字行總數（語言無關的度量標準）

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            int: 總行數
        """
        doc = fitz.open(pdf_path)
        total_lines = 0
        for page in doc:
            blocks = page.get_text("dict")["blocks"]
            for block in blocks:
                if block["type"] == 0:  # text block
                    total_lines += len(block.get("lines", []))
        doc.close()
        return total_lines

    # ==================== 字體分析 ====================

    @staticmethod
    def get_font_sizes(pdf_path: str) -> List[Dict]:
        """
        獲取所有字體大小信息

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            List[Dict]: 字體信息列表，每項包含 font, size, text, page
        """
        doc = fitz.open(pdf_path)
        fonts = []

        for page_num in range(len(doc)):
            page = doc[page_num]
            blocks = page.get_text("dict")["blocks"]

            for block in blocks:
                if block["type"] == 0:  # text block
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            fonts.append({
                                "font": span.get("font", "unknown"),
                                "size": span.get("size", 0),
                                "text": span.get("text", ""),
                                "page": page_num + 1
                            })

        doc.close()
        return fonts

    @staticmethod
    def has_small_fonts(pdf_path: str, threshold: float = 1.0) -> Tuple[bool, int]:
        """
        檢查是否有極小字體

        Args:
            pdf_path: PDF 文件路徑
            threshold: 字體大小閾值，小於此值視為極小字體

        Returns:
            Tuple[bool, int]: (是否有極小字體, 極小字體字符數)
        """
        fonts = PDFAnalyzer.get_font_sizes(pdf_path)
        small_fonts = [f for f in fonts if f['size'] < threshold]
        small_char_count = sum(len(f['text']) for f in small_fonts)
        return len(small_fonts) > 0, small_char_count

    # ==================== 版面分析 ====================

    @staticmethod
    def extract_text_boxes(pdf_path: str) -> List[Tuple[float, float, float, float]]:
        """
        提取所有文字框的位置

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            List[Tuple]: 文字框坐標列表 (x0, y0, x1, y1)
        """
        doc = fitz.open(pdf_path)
        boxes = []
        for page in doc:
            blocks = page.get_text("dict")["blocks"]
            for block in blocks:
                if block["type"] == 0:  # text block
                    boxes.append(tuple(block["bbox"]))
        doc.close()
        return boxes

    @staticmethod
    def compare_bbox_positions(
        boxes1: List[tuple],
        boxes2: List[tuple],
        tolerance: float = 50.0
    ) -> float:
        """
        比較兩組文字框的位置相似度

        Args:
            boxes1: 第一組文字框坐標
            boxes2: 第二組文字框坐標
            tolerance: 位置容差（像素）

        Returns:
            float: 相似度 (0-1)
        """
        if not boxes1 or not boxes2:
            return 0.0

        # 計算能匹配的框的比例
        matches = 0
        for box1 in boxes1:
            for box2 in boxes2:
                # 檢查位置是否接近
                if (abs(box1[0] - box2[0]) < tolerance and
                    abs(box1[1] - box2[1]) < tolerance):
                    matches += 1
                    break

        similarity = matches / max(len(boxes1), len(boxes2))
        return similarity

    @staticmethod
    def get_page_text_density(pdf_path: str, page_num: int) -> float:
        """
        計算特定頁面的文字密度（字符數/頁面面積）

        Args:
            pdf_path: PDF 文件路徑
            page_num: 頁碼（從 0 開始）

        Returns:
            float: 文字密度
        """
        doc = fitz.open(pdf_path)
        if page_num >= len(doc):
            doc.close()
            return 0.0

        page = doc[page_num]
        rect = page.rect
        area = rect.width * rect.height
        text = page.get_text()
        density = len(text.strip()) / area if area > 0 else 0
        doc.close()
        return density

    # ==================== 方向分析 ====================

    @staticmethod
    def check_text_orientation(pdf_path: str, page_num: int) -> dict:
        """
        檢查文字方向統計

        Args:
            pdf_path: PDF 文件路徑
            page_num: 頁碼（從 0 開始）

        Returns:
            dict: 文字方向統計 {"horizontal": n, "vertical": n, "flipped": n}
        """
        doc = fitz.open(pdf_path)
        if page_num >= len(doc):
            doc.close()
            return {}

        page = doc[page_num]
        blocks = page.get_text("dict")["blocks"]

        directions = {
            "horizontal": 0,
            "vertical": 0,
            "flipped": 0,
        }

        for block in blocks:
            if block["type"] == 0:
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        dir_vec = span.get("dir", (1, 0))
                        if abs(dir_vec[1]) > 0.5:  # 垂直
                            directions["vertical"] += 1
                        elif dir_vec[0] < 0:  # 翻轉
                            directions["flipped"] += 1
                        else:  # 正常橫排
                            directions["horizontal"] += 1

        doc.close()
        return directions

    # ==================== 頁面屬性 ====================

    @staticmethod
    def get_page_count(pdf_path: str) -> int:
        """
        獲取頁面數

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            int: 頁面數
        """
        doc = fitz.open(pdf_path)
        count = len(doc)
        doc.close()
        return count

    @staticmethod
    def get_image_count(pdf_path: str) -> int:
        """
        獲取圖片總數

        Args:
            pdf_path: PDF 文件路徑

        Returns:
            int: 圖片總數
        """
        doc = fitz.open(pdf_path)
        total = sum(len(doc[i].get_images()) for i in range(len(doc)))
        doc.close()
        return total

    # ==================== 進階分析（用於檢測翻轉問題）====================

    @staticmethod
    def get_detailed_spans(pdf_path: str, page_num: int) -> List[Dict]:
        """
        獲取頁面上所有 span 的詳細信息（用於翻轉檢測）

        Args:
            pdf_path: PDF 文件路徑
            page_num: 頁碼（從 0 開始）

        Returns:
            List[Dict]: span 信息列表，包含字體、大小、位置、方向等
        """
        doc = fitz.open(pdf_path)
        if page_num >= len(doc):
            doc.close()
            return []

        page = doc[page_num]
        blocks = page.get_text("dict")["blocks"]
        spans = []

        for block in blocks:
            if block["type"] == 0:  # text block
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        spans.append({
                            'text': span.get("text", ""),
                            'font': span.get("font", ""),
                            'size': span.get("size", 0),
                            'bbox': span.get("bbox", (0, 0, 0, 0)),
                            'origin': span.get("origin", (0, 0)),
                            'dir': span.get("dir", (1, 0)),  # 文字方向向量
                            'ascender': span.get("ascender", 0),
                            'descender': span.get("descender", 0),
                        })

        doc.close()
        return spans

    @staticmethod
    def analyze_coordinate_system(pdf_path: str, page_num: int) -> Dict:
        """
        分析座標系統是否正常

        Args:
            pdf_path: PDF 文件路徑
            page_num: 頁碼（從 0 開始）

        Returns:
            Dict: 座標系統分析結果
        """
        spans = PDFAnalyzer.get_detailed_spans(pdf_path, page_num)

        if not spans:
            return {
                'coord_system': 'unknown',
                'y_increases_downward': None,
                'suspicious': False
            }

        # 檢查 Y 座標是否向下遞增（正常 PDF）
        y_coords = [s['bbox'][1] for s in spans]  # Y0
        if len(y_coords) < 2:
            return {
                'coord_system': 'insufficient_data',
                'y_increases_downward': None,
                'suspicious': False
            }

        # 計算相鄰 span 的 Y 座標變化
        y_diffs = [y_coords[i+1] - y_coords[i] for i in range(len(y_coords) - 1)]
        positive_count = sum(1 for d in y_diffs if d > 0)
        negative_count = sum(1 for d in y_diffs if d < 0)

        y_increases_downward = positive_count > negative_count

        # 如果方向不一致，可能有問題
        suspicious = min(positive_count, negative_count) > len(y_diffs) * 0.3

        return {
            'coord_system': 'normal' if y_increases_downward else 'possibly_flipped',
            'y_increases_downward': y_increases_downward,
            'suspicious': suspicious,
            'positive_count': positive_count,
            'negative_count': negative_count
        }
