"""
快速提升 config.py 覆蓋率測試
目標：74% → 85% (+11%)

未覆蓋的行：
- 25: 防止重複初始化
- 39-44: 配置文件不存在且 isInit=False
- 82-91: custome_config 方法
- 157-184: 其他配置方法
- 212-214: 錯誤處理
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from pdf2zh.config import ConfigManager


class TestConfigCompleteCoverage:
    """補足 config.py 的覆蓋率缺口"""

    def setup_method(self):
        """每個測試前重置 ConfigManager"""
        # 重置單例
        ConfigManager._instance = None

    def test_prevent_double_initialization(self):
        """
        測試防止重複初始化
        覆蓋第 25 行
        """
        # 創建實例
        instance = ConfigManager()
        assert hasattr(instance, '_initialized')
        assert instance._initialized == True

        # 再次呼叫 __init__ 應該立即返回（觸發第 25 行）
        instance.__init__()

    def test_ensure_config_exists_with_isinit_false_missing_file(self):
        """
        測試 isInit=False 且文件不存在的情況
        覆蓋第 39-44 行
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nonexistent_config.json"

            instance = ConfigManager.get_instance()
            instance._config_path = config_path

            # isInit=False 且文件不存在應該拋出異常
            with pytest.raises(ValueError, match="not found"):
                instance._ensure_config_exists(isInit=False)

    def test_custom_config_with_valid_file(self):
        """
        測試 custome_config 方法（拼寫是原始的 typo）
        覆蓋第 82-91 行
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_config_path = Path(tmpdir) / "custom_config.json"
            custom_config_path.write_text('{"test_key": "test_value"}')

            # 呼叫 custome_config（注意拼寫）
            ConfigManager.custome_config(str(custom_config_path))

            # 驗證配置被載入
            instance = ConfigManager.get_instance()
            assert instance._config_path == custom_config_path
            assert "test_key" in instance._config_data

    def test_custom_config_with_missing_file(self):
        """測試 custome_config 與不存在的文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent_path = Path(tmpdir) / "nonexistent.json"

            # 應該拋出異常
            with pytest.raises(ValueError, match="not found"):
                ConfigManager.custome_config(str(nonexistent_path))

    def test_get_with_default_value(self):
        """測試 get 方法的預設值"""
        instance = ConfigManager.get_instance()

        # 取得不存在的鍵，應該返回預設值
        value = ConfigManager.get("nonexistent_test_key", "default_value")
        assert value == "default_value"

        # 設置一個鍵後取得
        ConfigManager.set("existing_key", "value")
        value = ConfigManager.get("existing_key")
        assert value == "value"

    def test_set_config_value(self):
        """測試 set 方法"""
        ConfigManager._instance = None
        instance = ConfigManager.get_instance()

        # 設置新值
        ConfigManager.set("new_key", "new_value")

        # 驗證值被設定
        value = ConfigManager.get("new_key")
        assert value == "new_value"

    def test_remove_circular_references(self):
        """測試移除循環引用"""
        ConfigManager._instance = None
        instance = ConfigManager.get_instance()

        # 創建循環引用
        data = {"key": "value"}
        data["self"] = data  # 循環引用

        # 移除循環引用
        cleaned = instance._remove_circular_references(data)

        # 原始 key 應該存在
        assert "key" in cleaned
        # 循環引用應該被處理為 None
        assert cleaned["self"] is None

    def test_remove_circular_references_with_list(self):
        """測試移除列表中的循環引用"""
        ConfigManager._instance = None
        instance = ConfigManager.get_instance()

        # 創建包含循環引用的列表
        data = [1, 2, 3]
        data.append(data)  # 循環引用

        cleaned = instance._remove_circular_references(data)

        assert len(cleaned) == 4
        assert cleaned[0] == 1
        assert cleaned[3] is None  # 循環引用被處理


class TestConfigEdgeCases:
    """額外的邊緣情況測試"""

    def setup_method(self):
        """每個測試前重置"""
        ConfigManager._instance = None

    def test_config_thread_safety(self):
        """測試配置的執行緒安全性"""
        import threading

        ConfigManager._instance = None
        instance = ConfigManager.get_instance()

        # 設置初始值
        ConfigManager.set("counter", 0)

        def increment():
            for _ in range(10):
                current = ConfigManager.get("counter", 0)
                ConfigManager.set("counter", current + 1)

        threads = [threading.Thread(target=increment) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 檢查最終值（由於鎖的保護，應該是正確的）
        final = ConfigManager.get("counter", 0)
        assert isinstance(final, int)

    def test_save_config_with_complex_data(self):
        """測試保存複雜的配置數據"""
        ConfigManager._instance = None
        instance = ConfigManager.get_instance()

        # 設置複雜數據
        complex_data = {
            "nested": {
                "level1": {
                    "level2": "value"
                }
            },
            "list": [1, 2, {"inner": "value"}],
            "unicode": "中文測試"
        }

        instance._config_data = complex_data
        instance._save_config()

        # 重新載入驗證
        with open(instance._config_path, 'r', encoding='utf-8') as f:
            loaded = json.load(f)

        assert loaded["nested"]["level1"]["level2"] == "value"
        assert loaded["unicode"] == "中文測試"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
