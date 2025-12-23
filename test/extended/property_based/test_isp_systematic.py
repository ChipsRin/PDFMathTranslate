"""
Input Space Partitioning (ISP) 系統化測試 - 統計報告增強版

功能：
1. 自動掃描並分類 PDF
2. 執行翻譯與驗證
3. [New] 最終生成 ISP 維度失敗率統計報告
"""

import pytest
import fitz  # PyMuPDF
import subprocess
import json
from pathlib import Path
from typing import Dict, Tuple, List
from dataclasses import dataclass
from collections import defaultdict, Counter
from datetime import datetime
from utils.pdf_analyzer import PDFAnalyzer
# ==========================================
# 1. 資料結構定義
# ==========================================

@dataclass
class PDFCharacteristics:
    """PDF 的維度特徵"""
    pdf_version: str
    font_size_category: str
    font_type_category: str
    image_density: str
    page_count_category: str
    content_complexity: str
    layout_label: str  # 佈局維度

    # 原始數據
    min_font_size: float
    max_font_size: float
    avg_font_size: float
    total_chars: int
    total_images: int
    page_count: int
    has_math_fonts: bool
    has_tables: bool

# ==========================================
# 2. ISP 維度分類器 (邏輯保持不變)
# ==========================================

class ISPDimensionClassifier:
    """ISP 維度分類器"""

    @staticmethod
    def classify_pdf_version(doc: fitz.Document) -> str:
        version = doc.metadata.get("format", "PDF-1.4")
        if any(v in version for v in ["1.1", "1.2", "1.3"]): return "早期版本 (≤1.3)"
        elif any(v in version for v in ["1.4", "1.5", "1.6"]): return "中期版本 (1.4-1.6)"
        return "現代版本 (≥1.7)"

    @staticmethod
    def classify_font_size(doc: fitz.Document) -> Tuple[str, float, float, float]:
        font_sizes = []
        sample_pages = doc[:min(len(doc), 5)]
        for page in sample_pages:
            blocks = page.get_text("dict")["blocks"]
            for block in blocks:
                if block["type"] == 0:
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            if span.get("size", 0) > 0: font_sizes.append(span["size"])

        if not font_sizes: return "無文字", 0, 0, 0
        min_s, max_s, avg_s = min(font_sizes), max(font_sizes), sum(font_sizes)/len(font_sizes)

        # 方案1: 計算極小字體比例
        tiny_count = sum(1 for s in font_sizes if s < 1.0)
        tiny_ratio = tiny_count / len(font_sizes)

        if tiny_ratio > 0.10:  # >10%
            return "大量極小字體 (>10%)", min_s, max_s, avg_s
        elif tiny_ratio > 0:   # <10% but exists
            return "少量極小字體 (<10%)", min_s, max_s, avg_s
        elif max_s > 24.0:
            return "含極大字體 (>24pt)", min_s, max_s, avg_s
        return "標準字體範圍 (1-24pt)", min_s, max_s, avg_s

    @staticmethod
    def classify_font_type(doc: fitz.Document) -> Tuple[str, bool]:
        font_names = set()
        for i in range(min(len(doc), 5)):
            for f in doc.get_page_fonts(i): font_names.add(f[3])
        
        math_patterns = ["CMM", "CMSY", "CMEX", "CMMI", "rsfs", "txsy"]
        has_math = any(p in f for f in font_names for p in math_patterns)
        if has_math: return "含數學字體", True
        elif any("+" in f for f in font_names): return "含嵌入字體", False
        return "標準字體", False

    @staticmethod
    def classify_image_density(doc: fitz.Document) -> Tuple[str, int]:
        total_images = sum(len(p.get_images()) for p in doc)
        if total_images == 0: return "無圖片", 0
        elif total_images / max(1, len(doc)) < 2: return "稀疏圖片", total_images
        return "密集圖片", total_images

    @staticmethod
    def classify_page_count(doc: fitz.Document) -> Tuple[str, int]:
        c = len(doc)
        if c == 1: return "單頁", c
        elif c <= 10: return "少量頁面", c
        return "大量頁面", c

    @staticmethod
    def classify_content_complexity(doc: fitz.Document) -> str:
        sample = doc[0]
        if len(sample.get_images()) == 0 and len(sample.get_text()) > 1000: return "純文字"
        elif len(sample.get_images()) > 0: return "圖文混排"
        return "其他"

    @staticmethod
    def classify_layout_complexity(doc: fitz.Document) -> dict:
        if len(doc) == 0: return {"column_type": "無內容", "has_tables": False, "layout_summary": "無內容"}
        
        sample_pages = doc[:min(3, len(doc))]
        column_results = []
        table_detected = False

        for page in sample_pages:
            try:
                if page.find_tables().tables: table_detected = True
            except: pass

            blocks = page.get_text("blocks")
            text_blocks = [b for b in blocks if b[6] == 0 and len(b[4].strip()) > 5]
            if text_blocks:
                w = page.rect.width
                centers = [(b[0] + b[2]) / 2 for b in text_blocks]
                left = sum(1 for c in centers if c < w * 0.45)
                right = sum(1 for c in centers if c > w * 0.55)
                column_results.append("多欄 (Multi)" if left > 2 and right > 2 else "單欄 (Single)")

        final_col = max(set(column_results), key=column_results.count) if column_results else "單欄 (Single)"
        return {
            "column_type": final_col,
            "has_tables": table_detected,
            "layout_summary": f"{final_col} + {'有表格' if table_detected else '無表格'}"
        }

    @classmethod
    def analyze_pdf(cls, pdf_path: str) -> PDFCharacteristics:
        """完整分析 PDF 的所有維度特徵 (含錯誤處理)"""
        
        # 1. 嘗試打開文件
        try:
            doc = fitz.open(pdf_path)
        except Exception as e:
            # 如果連打開都失敗，回傳一個代表「損毀」的特徵物件
            print(f"   ❌ [嚴重損毀] 無法開啟 PDF: {e}")
            return cls._create_corrupted_characteristics("無法開啟")

        try:
            # 2. 執行各項分析
            # 注意：這裡雖然 PyMuPDF 會印出錯誤訊息到 Console，但通常不會拋出 Python Exception
            # 除非檔案真的爛到無法讀取 metadata
            
            pdf_version = cls.classify_pdf_version(doc)
            font_size_cat, min_fs, max_fs, avg_fs = cls.classify_font_size(doc)
            font_type_cat, has_math = cls.classify_font_type(doc)
            image_cat, img_count = cls.classify_image_density(doc)
            page_cat, pg_count = cls.classify_page_count(doc)
            content_cat = cls.classify_content_complexity(doc)
            layout_info = cls.classify_layout_complexity(doc)

            total_chars = sum(len(page.get_text()) for page in doc)
            
        except Exception as e:
            # 如果在分析過程中崩潰 (例如 XObject 錯誤導致 get_text 失敗)
            print(f"   ⚠️ [部分損毀] 分析過程發生錯誤: {e}")
            return cls._create_corrupted_characteristics("內容解析失敗")
            
        finally:
            doc.close()

        return PDFCharacteristics(
            pdf_version=pdf_version,
            font_size_category=font_size_cat,
            font_type_category=font_type_cat,
            image_density=image_cat,
            page_count_category=page_cat,
            content_complexity=content_cat,
            layout_label=layout_info["layout_summary"],
            min_font_size=min_fs,
            max_font_size=max_fs,
            avg_font_size=avg_fs,
            total_chars=total_chars,
            total_images=img_count,
            page_count=pg_count,
            has_math_fonts=has_math,
            has_tables=layout_info["has_tables"]
        )

    @staticmethod
    def _create_corrupted_characteristics(reason: str) -> PDFCharacteristics:
        """輔助方法：生成一個代表損毀檔案的特徵物件"""
        return PDFCharacteristics(
            pdf_version="Unknown",
            font_size_category="Unknown",
            font_type_category="Unknown",
            image_density="Unknown",
            page_count_category="Unknown",
            content_complexity=f"損毀: {reason}",
            layout_label="Corrupted",
            min_font_size=0, max_font_size=0, avg_font_size=0,
            total_chars=0, total_images=0, page_count=0,
            has_math_fonts=False, has_tables=False
        )

# ==========================================
# 3. 屬性驗證器 (邏輯保持不變)
# ==========================================

class PropertyValidator:
    @staticmethod
    def validate_content_preservation(original_path, translated_path):
        """
        內容保存驗證 - 分級警告系統
        返回: (severity_level, message, details)
        severity_level: "嚴重" | "中度警告" | "輕度警告" | "提示" | "正常" | "錯誤"
        """
        if not Path(translated_path).exists():
            return "錯誤", "翻譯文件不存在", {}

        # 使用 PDFAnalyzer 計算字符數和真正的行數（與 metamorphic test 一致）
        c1 = PDFAnalyzer.get_text_length(original_path)
        c2 = PDFAnalyzer.get_text_length(translated_path)
        l1 = PDFAnalyzer.count_lines(original_path)
        l2 = PDFAnalyzer.count_lines(translated_path)

        if c1 == 0: return "正常", "無文字跳過", {}

        cr, lr = (c2/c1 if c1>0 else 0), (l2/l1 if l1>0 else 0)
        details = {"char_ratio": cr, "line_ratio": lr}

        # 分級判斷系統：只根據行數判斷（更準確，不受英譯中字符減少影響）
        if lr < 0.2:  # 行數丟失 >80%
            return "嚴重", f"行數嚴重丟失 (line:{lr:.2f}, {l1}→{l2} lines)", details
        elif lr < 0.5:  # 行數丟失 >50%
            return "中度警告", f"行數明顯減少 (line:{lr:.2f})", details
        elif lr < 0.8:  # 行數丟失 >20%
            return "提示", f"行數略減 (line:{lr:.2f})", details
        else:
            return "正常", f"內容完整 (line:{lr:.2f})", details

    @staticmethod
    def validate_structure_preservation(original_path, translated_path):
        if not Path(translated_path).exists(): return False, "無翻譯檔", {}
        d1, d2 = fitz.open(original_path), fitz.open(translated_path)
        res = (len(d1) == len(d2))
        msg = "頁數一致" if res else f"頁數改變 ({len(d1)}->{len(d2)})"
        d1.close(); d2.close()
        return res, msg, {}

# ==========================================
# 4. 測試主程式 (報告增強版)
# ==========================================

class TestISPSystematic:
    """ISP 系統化測試 - 含 Markdown 統計報告"""

    def test_full_isp_workflow_with_report(self):
        # 設定你的測試檔案列表
        test_files = [
            "test/fixtures/sample_pdfs/icml01-ffq_raw.pdf",
            "test/fixtures/sample_pdfs/0908.0032v3.pdf",
            "test/fixtures/sample_pdfs/1209.0095v1.pdf",
            "test/fixtures/sample_pdfs/1308.1749v1.pdf",
            "test/fixtures/sample_pdfs/1506.00956v1.pdf",
            "test/fixtures/sample_pdfs/1606.00863v2.pdf",
            "test/fixtures/sample_pdfs/1706.03762v7.pdf",
            "test/fixtures/sample_pdfs/1809.00806v3.pdf",
            "test/fixtures/sample_pdfs/1908.01115v3.pdf",
            "test/fixtures/sample_pdfs/2206.00011v1.pdf",
            "test/fixtures/sample_pdfs/2406.09676v2.pdf",
            "test/fixtures/sample_pdfs/2503.00102v2.pdf",
            "test/fixtures/sample_pdfs/2511.00017v1.pdf",
            "test/fixtures/sample_pdfs/0608006v1.pdf",
            "test/fixtures/sample_pdfs/13205_2024_Article_4159.pdf",
            "test/fixtures/sample_pdfs/s13205-024-04159-4.pdf",
        ]

        # 統計容器
        isp_stats = defaultdict(lambda: defaultdict(lambda: {
            "total": 0, "嚴重": 0, "中度警告": 0, "輕度警告": 0, "提示": 0, "正常": 0, "錯誤": 0
        }))

        warnings_log = []  
        total_processed = 0

        print("\n" + "="*80)
        print("🚀 ISP 系統化測試啟動 (統計模式)")
        print("="*80)

        for filepath in test_files:
            p = Path(filepath)
            if not p.exists():
                print(f"⚠️  跳過: {p.name}")
                continue
            
            total_processed += 1
            print(f"\n📄 [分析] {p.name}")

            # 1. 分析特徵
            try:
                chars = ISPDimensionClassifier.analyze_pdf(str(p))
                print(f"   ISP特徵: {chars.layout_label} | {chars.font_size_category}")
            except Exception as e:
                print(f"   ❌ 分析失敗: {e}")
                continue

            # 2. 執行翻譯
            trans_path = Path(f"test/fixtures/translated_pdfs/{p.stem}-mono.pdf")
            if not trans_path.exists():
                self._run_translation_cli(p, trans_path.parent)

            # 3. 驗證與統計歸因
            severity_level = "正常"
            message = ""

            s_ok, s_msg, _ = PropertyValidator.validate_structure_preservation(str(p), str(trans_path))
            if not s_ok:
                severity_level = "嚴重"
                message = f"[結構] {s_msg}"

            c_severity, c_msg, c_details = PropertyValidator.validate_content_preservation(str(p), str(trans_path))

            if severity_level == "正常":
                severity_level = c_severity
                message = f"[內容] {c_msg}"
            else:
                message += f" + [內容] {c_msg}"

            # 4. 記錄統計
            dimensions_to_track = {
                "Layout": chars.layout_label,
                "Version": chars.pdf_version,
                "Font": chars.font_size_category,
                "Content": chars.content_complexity
            }

            for dim_name, category in dimensions_to_track.items():
                isp_stats[dim_name][category]["total"] += 1
                isp_stats[dim_name][category][severity_level] += 1

            # 輸出 Console 狀態
            severity_icons = {"正常": "✅", "提示": "💡", "輕度警告": "⚠️", "中度警告": "🟠", "嚴重": "🔴", "錯誤": "❌"}
            print(f"   {severity_icons.get(severity_level, '❓')} {severity_level}: {message}")

            if severity_level != "正常":
                warnings_log.append((p.name, severity_level, message, chars, c_details))

        # ==========================================
        # 5. 生成報告數據 (Dictionary)
        # ==========================================
        
        # 統計各警告等級的總數
        total_serious = len([w for w in warnings_log if w[1] == "嚴重"])
        total_medium = len([w for w in warnings_log if w[1] == "中度警告"])
        total_light = len([w for w in warnings_log if w[1] == "輕度警告"])
        total_hint = len([w for w in warnings_log if w[1] == "提示"])
        total_normal = total_processed - len(warnings_log)

        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_pdfs": total_processed,
            "summary": {
                "嚴重": total_serious, "中度警告": total_medium, "輕度警告": total_light,
                "提示": total_hint, "正常": total_normal
            },
            "isp_stats": isp_stats,
            "warnings_log": warnings_log
        }

        # ==========================================
        # 6. 輸出 Markdown 報告
        # ==========================================
        md_path = Path("test/extended/isp_test_report.md")
        self._generate_markdown_report(report_data, md_path)
        
        # 同時保留 JSON 以備不時之需
        json_path = Path("test/extended/isp_test_report.json")
        # 轉換 defaultdict 為普通 dict 以便 JSON 序列化
        json_serializable = json.loads(json.dumps(report_data, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o)))
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_serializable, f, indent=2, ensure_ascii=False)

        print("\n" + "="*80)
        print(f"📊 測試完成！")
        print(f"📝 Markdown 報告已生成: {md_path}")
        print(f"📝 JSON 數據已備份: {json_path}")
        print("="*80)

    def _generate_markdown_report(self, data, output_path: Path):
        """生成美觀的 Markdown 表格報告"""
        
        timestamp = data['timestamp']
        total = data['total_pdfs']
        summary = data['summary']
        stats = data['isp_stats']
        warnings = data['warnings_log']

        # 計算 Pass Rate (正常 + 提示 都算 Pass)
        pass_count = summary['正常'] + summary['提示']
        pass_rate = (pass_count / total * 100) if total > 0 else 0
        
        # 決定整體狀態圖示
        status_icon = "🟢 優秀" if pass_rate >= 90 else "🟡 需注意" if pass_rate >= 70 else "🔴 危險"

        md_content = f"""# 📑 ISP 系統化測試報告

**測試時間:** {timestamp}  
**測試樣本:** {total} 份 PDF  
**整體狀態:** {status_icon} (合格率: {pass_rate:.1f}%)

## 1. 執行摘要 (Executive Summary)

| 等級 | 圖示 | 數量 | 佔比 | 說明 |
| :--- | :---: | :---: | :---: | :--- |
| **嚴重** | 🔴 | {summary['嚴重']} | {summary['嚴重']/total*100:.1f}% | 結構破壞、內容丟失 > 70% |
| **中度** | 🟠 | {summary['中度警告']} | {summary['中度警告']/total*100:.1f}% | 內容丟失 50-70% |
| **輕度** | ⚠️ | {summary['輕度警告']} | {summary['輕度警告']/total*100:.1f}% | 行數顯著減少 |
| **提示** | 💡 | {summary['提示']} | {summary['提示']/total*100:.1f}% | 輕微差異 (翻譯特性) |
| **正常** | ✅ | {summary['正常']} | {summary['正常']/total*100:.1f}% | 結構與內容完整 |

---

## 2. 維度熱點分析 (Dimensional Analysis)

以下表格顯示哪些 PDF 類型最容易出錯。**排序依據：問題嚴重程度**。

"""
        # 生成各維度的表格
        for dim_name, categories in stats.items():
            md_content += f"### 🔹 維度: {dim_name}\n\n"
            md_content += f"| 類別名稱 | 總數 | 🔴 嚴重 | 🟠 中度 | ⚠️ 輕度 | ✅ 正常 | 合格率 |\n"
            md_content += f"| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"

            # 排序邏輯：嚴重 > 中度 > 輕度
            def sort_key(item):
                d = item[1]
                return (d['嚴重'] * 100 + d['中度警告'] * 10 + d['輕度警告'])

            sorted_cats = sorted(categories.items(), key=sort_key, reverse=True)

            for cat, d in sorted_cats:
                cat_pass = d['正常'] + d['提示']
                cat_rate = (cat_pass / d['total'] * 100) if d['total'] > 0 else 0
                
                # 粗體標示表現最差的類別
                cat_display = f"**{cat}**" if d['嚴重'] > 0 else cat
                
                md_content += f"| {cat_display} | {d['total']} | {d['嚴重']} | {d['中度警告']} | {d['輕度警告']} | {d['正常']} | {cat_rate:.0f}% |\n"
            
            md_content += "\n"

        md_content += """---

## 3. 詳細問題清單 (Failure Log)

僅列出非正常的測試案例。

| 檔案名稱 | 等級 | 問題描述 | 佈局類型 | 字體特徵 |
| :--- | :---: | :--- | :--- | :--- |
"""
        # 生成詳細 Log 表格
        if not warnings:
            md_content += "| (無) | ✅ | 所有測試通過 | - | - |\n"
        else:
            # 依嚴重程度排序
            severity_order = {"嚴重": 0, "中度警告": 1, "輕度警告": 2, "提示": 3}
            sorted_warnings = sorted(warnings, key=lambda x: severity_order.get(x[1], 99))

            icon_map = {"嚴重": "🔴", "中度警告": "🟠", "輕度警告": "⚠️", "提示": "💡"}

            for fname, sev, msg, chars, _ in sorted_warnings:
                icon = icon_map.get(sev, "❓")
                # 簡化佈局描述以免表格爆開
                layout_short = chars.layout_label.split(" + ")[0] 
                md_content += f"| `{fname}` | {icon} | {msg} | {layout_short} | {chars.font_size_category} |\n"

        # 寫入檔案
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)

    def _run_translation_cli(self, original, output_dir):
        """輔助方法: 封裝 subprocess 呼叫"""
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                "python", "-m", "pdf2zh.pdf2zh", str(original),
                "--service", "google", "--lang-in", "en", "--lang-out", "zh",
                "--output", str(output_dir), "--thread", "1", "--ignore-cache"
            ], capture_output=True, check=True, timeout=500)
        except Exception as e:
            print(f"   (翻譯執行錯誤: {e})")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])