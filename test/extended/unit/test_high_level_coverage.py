"""
快速提升 high_level.py 覆蓋率測試
目標：17% → 30% (+13%)

重點測試：
- check_files() 文件檢查函數
- download_remote_fonts() 字體下載函數
- noto_list 語言列表
- 基本的輔助函數
"""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from pdf2zh.high_level import check_files, download_remote_fonts, noto_list, NOTO_NAME


class TestCheckFiles(unittest.TestCase):
    """測試 check_files 函數"""

    def test_check_files_with_existing_files(self):
        """測試存在的文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 創建測試文件
            file1 = Path(tmpdir) / "test1.txt"
            file2 = Path(tmpdir) / "test2.txt"
            file1.write_text("test")
            file2.write_text("test")

            files = [str(file1), str(file2)]
            missing = check_files(files)

            self.assertEqual(missing, [])

    def test_check_files_with_missing_files(self):
        """測試不存在的文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = Path(tmpdir) / "exists.txt"
            file1.write_text("test")

            missing_file = Path(tmpdir) / "missing.txt"

            files = [str(file1), str(missing_file)]
            missing = check_files(files)

            self.assertEqual(len(missing), 1)
            self.assertIn(str(missing_file), missing)

    def test_check_files_with_http_urls(self):
        """測試 HTTP URL 被排除"""
        files = [
            "http://example.com/file.pdf",
            "https://example.com/file.pdf",
            "/local/file.pdf"
        ]

        missing = check_files(files)

        # HTTP/HTTPS URLs should be excluded
        self.assertEqual(len(missing), 1)
        self.assertIn("/local/file.pdf", missing)

    def test_check_files_with_all_http_urls(self):
        """測試全部是 HTTP URL"""
        files = [
            "http://example.com/file1.pdf",
            "https://example.com/file2.pdf",
        ]

        missing = check_files(files)

        # All URLs excluded, so no missing files
        self.assertEqual(missing, [])

    def test_check_files_with_empty_list(self):
        """測試空列表"""
        missing = check_files([])
        self.assertEqual(missing, [])

    def test_check_files_mixed_scenarios(self):
        """測試混合場景"""
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_file = Path(tmpdir) / "exists.txt"
            existing_file.write_text("test")

            missing_file = Path(tmpdir) / "missing.txt"

            files = [
                "http://example.com/remote.pdf",
                str(existing_file),
                str(missing_file),
                "https://example.com/another.pdf"
            ]

            missing = check_files(files)

            # Only local missing file should be in result
            self.assertEqual(len(missing), 1)
            self.assertIn(str(missing_file), missing)


class TestDownloadRemoteFonts(unittest.TestCase):
    """測試 download_remote_fonts 函數"""

    @patch('pdf2zh.high_level.ConfigManager.get')
    @patch('pdf2zh.high_level.Path')
    def test_download_remote_fonts_with_existing_path(self, mock_path, mock_config_get):
        """測試字體路徑已存在"""
        # Mock 字體路徑存在
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.as_posix.return_value = "/app/font.ttf"
        mock_path.return_value = mock_path_instance

        mock_config_get.return_value = "/app/font.ttf"

        result = download_remote_fonts("zh-cn")

        self.assertEqual(result, "/app/font.ttf")

    @patch('pdf2zh.high_level.ConfigManager.get')
    @patch('pdf2zh.high_level.Path')
    @patch('pdf2zh.high_level.get_font_and_metadata')
    def test_download_remote_fonts_with_missing_path(self, mock_get_font, mock_path, mock_config_get):
        """測試字體路徑不存在，需要下載"""
        # Mock 字體路徑不存在
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        mock_config_get.return_value = "/app/font.ttf"

        # Mock get_font_and_metadata 返回
        mock_font_path = MagicMock()
        mock_font_path.as_posix.return_value = "/downloaded/font.ttf"
        mock_get_font.return_value = (mock_font_path, {})

        result = download_remote_fonts("zh-cn")

        self.assertEqual(result, "/downloaded/font.ttf")
        mock_get_font.assert_called_once()

    @patch('pdf2zh.high_level.ConfigManager.get')
    @patch('pdf2zh.high_level.Path')
    def test_download_remote_fonts_different_languages(self, mock_path, mock_config_get):
        """測試不同語言的字體選擇"""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.as_posix.return_value = "/app/font.ttf"
        mock_path.return_value = mock_path_instance

        mock_config_get.return_value = "/app/font.ttf"

        # 測試中文
        result_cn = download_remote_fonts("zh-cn")
        self.assertIsNotNone(result_cn)

        # 測試日文
        result_ja = download_remote_fonts("ja")
        self.assertIsNotNone(result_ja)

        # 測試韓文
        result_ko = download_remote_fonts("ko")
        self.assertIsNotNone(result_ko)

        # 測試繁體中文
        result_tw = download_remote_fonts("zh-tw")
        self.assertIsNotNone(result_tw)

    @patch('pdf2zh.high_level.ConfigManager.get')
    @patch('pdf2zh.high_level.Path')
    def test_download_remote_fonts_case_insensitive(self, mock_path, mock_config_get):
        """測試語言代碼不區分大小寫"""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.as_posix.return_value = "/app/font.ttf"
        mock_path.return_value = mock_path_instance

        mock_config_get.return_value = "/app/font.ttf"

        # 大寫應該也能工作
        result = download_remote_fonts("ZH-CN")
        self.assertIsNotNone(result)

    @patch('pdf2zh.high_level.ConfigManager.get')
    @patch('pdf2zh.high_level.Path')
    def test_download_remote_fonts_noto_languages(self, mock_path, mock_config_get):
        """測試 noto_list 中的語言"""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.as_posix.return_value = "/app/GoNotoKurrent-Regular.ttf"
        mock_path.return_value = mock_path_instance

        mock_config_get.return_value = "/app/GoNotoKurrent-Regular.ttf"

        # 測試 noto_list 中的語言（如阿拉伯語）
        result = download_remote_fonts("ar")
        self.assertIsNotNone(result)


class TestConstants(unittest.TestCase):
    """測試常量"""

    def test_noto_name_constant(self):
        """測試 NOTO_NAME 常量"""
        self.assertEqual(NOTO_NAME, "noto")

    def test_noto_list_contains_expected_languages(self):
        """測試 noto_list 包含預期的語言"""
        # 測試一些關鍵語言
        self.assertIn("ar", noto_list)  # Arabic
        self.assertIn("hi", noto_list)  # Hindi
        self.assertIn("ru", noto_list)  # Russian
        self.assertIn("th", noto_list)  # Thai

    def test_noto_list_length(self):
        """測試 noto_list 的長度"""
        # noto_list 應該包含 19 種語言
        self.assertEqual(len(noto_list), 19)

    def test_noto_list_all_lowercase(self):
        """測試 noto_list 中所有語言代碼都是小寫"""
        for lang in noto_list:
            self.assertEqual(lang, lang.lower())


if __name__ == "__main__":
    unittest.main()
