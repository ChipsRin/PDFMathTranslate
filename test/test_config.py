import unittest
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

from pdf2zh.config import ConfigManager


class TestConfigManager(unittest.TestCase):
    """測試 ConfigManager 設定管理器"""

    def setUp(self):
        """每個測試前的準備工作"""
        # 1. 建立臨時目錄，避免影響真實設定檔
        self.temp_dir = tempfile.mkdtemp()
        self.test_config_path = Path(self.temp_dir) / "test_config.json"

        # 2. 重置 ConfigManager 單例（很重要！）
        ConfigManager._instance = None

        # 3. 備份環境變數（以免測試污染真實環境）
        self.original_env = os.environ.copy()

    def _setup_test_config(self):
        """設定測試用的 config path"""
        instance = ConfigManager.get_instance()
        instance._config_path = self.test_config_path
        instance._config_data = {}
        if self.test_config_path.exists():
            instance._load_config()
        else:
            self.test_config_path.parent.mkdir(parents=True, exist_ok=True)
            instance._save_config()
        return instance

    def tearDown(self):
        """每個測試後的清理工作"""
        # 1. 刪除臨時設定檔
        if self.test_config_path.exists():
            self.test_config_path.unlink()

        # 2. 刪除臨時目錄
        os.rmdir(self.temp_dir)

        # 3. 還原環境變數
        os.environ.clear()
        os.environ.update(self.original_env)

        # 4. 重置單例
        ConfigManager._instance = None

    # ==================== 基本讀寫測試 ====================

    def test_set_and_get(self):
        """測試：存入的值可以正確讀取"""
        self._setup_test_config()

        # 設定一個值
        ConfigManager.set("TEST_KEY", "test_value")

        # 讀取這個值
        result = ConfigManager.get("TEST_KEY")

        # 驗證：讀到的值應該和存入的一樣
        self.assertEqual(result, "test_value")

    def test_get_nonexistent_key(self):
        """測試：讀取不存在的 key 應該回傳 None"""
        self._setup_test_config()

        result = ConfigManager.get("NONEXISTENT_KEY")
        self.assertIsNone(result)

    def test_get_with_default(self):
        """測試：讀取不存在的 key 時，應該回傳預設值"""
        self._setup_test_config()

        result = ConfigManager.get("NONEXISTENT_KEY", default="default_value")
        self.assertEqual(result, "default_value")

    def test_delete(self):
        """測試：刪除 key 後應該讀不到"""
        self._setup_test_config()

        # 先存入一個值
        ConfigManager.set("TEST_KEY", "test_value")

        # 刪除它
        ConfigManager.delete("TEST_KEY")

        # 驗證：應該讀不到了
        result = ConfigManager.get("TEST_KEY")
        self.assertIsNone(result)

    def test_clear(self):
        """測試：clear 會清空所有設定"""
        self._setup_test_config()

        # 存入多個值
        ConfigManager.set("KEY1", "value1")
        ConfigManager.set("KEY2", "value2")

        # 清空
        ConfigManager.clear()

        # 驗證：所有值都讀不到了
        self.assertIsNone(ConfigManager.get("KEY1"))
        self.assertIsNone(ConfigManager.get("KEY2"))

    # ==================== 環境變數測試 ====================

    def test_env_var_first_time(self):
        """測試：第一次讀取時，環境變數會生效並寫入設定檔"""
        self._setup_test_config()

        # 設定環境變數
        os.environ["API_KEY"] = "env_value"

        # 第一次讀取（應該從環境變數讀取）
        result = ConfigManager.get("API_KEY")
        self.assertEqual(result, "env_value")

        # 驗證：環境變數的值被寫入設定檔了
        config_data = ConfigManager.all()
        self.assertEqual(config_data["API_KEY"], "env_value")

    def test_env_var_saved_to_config(self):
        """測試：從環境變數讀取的值會被寫入設定檔"""
        self._setup_test_config()

        # 設定環境變數
        os.environ["NEW_KEY"] = "env_value"

        # 第一次讀取（從環境變數）
        result = ConfigManager.get("NEW_KEY")
        self.assertEqual(result, "env_value")

        # 刪除環境變數
        del os.environ["NEW_KEY"]

        # 重置單例，讓它重新讀取設定檔
        ConfigManager._instance = None
        self._setup_test_config()

        # 第二次讀取（從設定檔）
        result = ConfigManager.get("NEW_KEY")
        # 應該還能讀到，因為已經寫入設定檔
        self.assertEqual(result, "env_value")

    # ==================== 翻譯器設定測試 ====================

    def test_set_and_get_translator(self):
        """測試：可以設定和讀取翻譯器設定"""
        self._setup_test_config()

        # 設定 Google 翻譯器的設定
        translator_envs = {
            "GOOGLE_API_KEY": "google-key-123"
        }
        ConfigManager.set_translator_by_name("google", translator_envs)

        # 讀取
        result = ConfigManager.get_translator_by_name("google")

        # 驗證
        self.assertEqual(result, translator_envs)

    def test_get_nonexistent_translator(self):
        """測試：讀取不存在的翻譯器應該回傳 None"""
        self._setup_test_config()

        result = ConfigManager.get_translator_by_name("nonexistent")
        self.assertIsNone(result)

    def test_update_translator(self):
        """測試：可以更新已存在的翻譯器設定"""
        self._setup_test_config()

        # 第一次設定
        ConfigManager.set_translator_by_name("openai", {
            "API_KEY": "old_key",
            "MODEL": "gpt-3.5"
        })

        # 更新設定
        ConfigManager.set_translator_by_name("openai", {
            "API_KEY": "new_key",
            "MODEL": "gpt-4"
        })

        # 讀取
        result = ConfigManager.get_translator_by_name("openai")

        # 驗證：應該是更新後的值
        self.assertEqual(result["API_KEY"], "new_key")
        self.assertEqual(result["MODEL"], "gpt-4")

    def test_multiple_translators_isolated(self):
        """測試：多個翻譯器的設定不會互相干擾"""
        self._setup_test_config()

        # 設定兩個不同的翻譯器
        ConfigManager.set_translator_by_name("google", {
            "API_KEY": "google_key"
        })
        ConfigManager.set_translator_by_name("openai", {
            "API_KEY": "openai_key"
        })

        # 讀取並驗證
        google_config = ConfigManager.get_translator_by_name("google")
        openai_config = ConfigManager.get_translator_by_name("openai")

        self.assertEqual(google_config["API_KEY"], "google_key")
        self.assertEqual(openai_config["API_KEY"], "openai_key")

    # ==================== 邊界情況測試 ====================

    def test_empty_string_value(self):
        """測試：可以存入空字串"""
        self._setup_test_config()

        ConfigManager.set("EMPTY_KEY", "")
        result = ConfigManager.get("EMPTY_KEY")
        self.assertEqual(result, "")

    def test_special_characters_in_value(self):
        """測試：可以存入包含特殊字元的值"""
        self._setup_test_config()

        special_value = "value with !@#$%^&*() 中文"
        ConfigManager.set("SPECIAL_KEY", special_value)
        result = ConfigManager.get("SPECIAL_KEY")
        self.assertEqual(result, special_value)

    def test_numeric_value(self):
        """測試：可以存入數字（會被轉成字串或保持數字格式）"""
        self._setup_test_config()

        ConfigManager.set("NUMBER_KEY", 123)
        result = ConfigManager.get("NUMBER_KEY")
        self.assertEqual(result, 123)

    def test_dict_value(self):
        """測試：可以存入字典"""
        self._setup_test_config()

        dict_value = {"nested": "value", "count": 42}
        ConfigManager.set("DICT_KEY", dict_value)
        result = ConfigManager.get("DICT_KEY")
        self.assertEqual(result, dict_value)


if __name__ == "__main__":
    unittest.main()
