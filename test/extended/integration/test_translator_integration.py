"""
翻譯器整合測試
目標：測試所有翻譯服務的整合

測試範圍：
- 主流翻譯器（Google, Bing, DeepL, AnythingLLM, OpenAI）
- 小眾翻譯器（ModelScope, Zhipu, Silicon, Gemini, Grok, Groq, Deepseek, QwenMt 等）
- 特殊翻譯器（Xinference, Azure, Tencent, Dify, Argos）
- 錯誤處理和環境變數配置
"""
import unittest
from unittest.mock import patch, MagicMock
import requests
import os
import pytest

from pdf2zh.config import ConfigManager
from pdf2zh.translator import (
    GoogleTranslator,
    BingTranslator,
    DeepLTranslator,
    AnythingLLMTranslator,
    OpenAITranslator,
    ModelScopeTranslator,
    ZhipuTranslator,
    SiliconTranslator,
    X302AITranslator,
    GeminiTranslator,
    GrokTranslator,
    GroqTranslator,
    DeepseekTranslator,
    OpenAIlikedTranslator,
    QwenMtTranslator,
    XinferenceTranslator,
    AzureTranslator,
    TencentTranslator,
    DifyTranslator,
    ArgosTranslator,
)


# ========== 主流翻譯器測試 ==========

class TestGoogleTranslator(unittest.TestCase):
    """測試 GoogleTranslator - 用 Mock 模擬 HTTP 請求"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div class="result-container">你好世界</div>'
            mock_get.return_value = mock_response

            result = translator.do_translate("Hello World")
            self.assertEqual(result, "你好世界")
            mock_get.assert_called_once()

    def test_translate_max_length(self):
        """測試：超過 5000 字元會被截斷"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div class="result-container">結果</div>'
            mock_get.return_value = mock_response

            long_text = "a" * 6000
            translator.do_translate(long_text)

            call_args = mock_get.call_args
            actual_text = call_args[1]['params']['q']
            self.assertEqual(len(actual_text), 5000)

    def test_translate_html_unescape(self):
        """測試：HTML 特殊字元能正確轉換"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div class="result-container">A &amp; B</div>'
            mock_get.return_value = mock_response

            result = translator.do_translate("A & B")
            self.assertEqual(result, "A & B")

    def test_translate_error_400(self):
        """測試：HTTP 400 錯誤的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = ''
            mock_get.return_value = mock_response

            result = translator.do_translate("Test")
            self.assertEqual(result, "IRREPARABLE TRANSLATION ERROR")

    def test_translate_with_special_characters(self):
        """測試：特殊字元的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div class="result-container">你好👋\n世界</div>'
            mock_get.return_value = mock_response

            result = translator.do_translate("Hello👋\nWorld")
            self.assertIsNotNone(result)


class TestBingTranslator(unittest.TestCase):
    """測試 BingTranslator - 測試兩階段請求流程"""

    def test_translate_success(self):
        """測試：正常翻譯流程（包含 token 取得）"""
        translator = BingTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get, \
             patch.object(translator.session, 'post') as mock_post:

            mock_get_response = MagicMock()
            mock_get_response.url = "https://www.bing.com/translator"
            mock_get_response.text = '''
                "ig":"ABC123"
                data-iid="translator.5678"
                params_AbusePreventionHelper = [123,"token_value",
            '''
            mock_get.return_value = mock_get_response

            mock_post_response = MagicMock()
            mock_post_response.json.return_value = [
                {"translations": [{"text": "你好世界"}]}
            ]
            mock_post.return_value = mock_post_response

            result = translator.do_translate("Hello World")
            self.assertEqual(result, "你好世界")
            self.assertTrue(mock_get.called)
            self.assertTrue(mock_post.called)

    def test_translate_max_length(self):
        """測試：超過 1000 字元會被截斷"""
        translator = BingTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get, \
             patch.object(translator.session, 'post') as mock_post:

            mock_get_response = MagicMock()
            mock_get_response.url = "https://www.bing.com/translator"
            mock_get_response.text = '''
                "ig":"ABC123"
                data-iid="translator.5678"
                params_AbusePreventionHelper = [123,"token_value",
            '''
            mock_get.return_value = mock_get_response

            mock_post_response = MagicMock()
            mock_post_response.json.return_value = [
                {"translations": [{"text": "結果"}]}
            ]
            mock_post.return_value = mock_post_response

            long_text = "a" * 1500
            translator.do_translate(long_text)

            call_args = mock_post.call_args
            actual_text = call_args[1]['data']['text']
            self.assertEqual(len(actual_text), 1000)


class TestTranslatorErrorHandling(unittest.TestCase):
    """測試翻譯器的錯誤處理"""

    def test_google_http_timeout(self):
        """測試：HTTP timeout 的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_get.side_effect = requests.Timeout("Connection timeout")

            with self.assertRaises(requests.Timeout):
                translator.do_translate("Test")

    def test_google_connection_error(self):
        """測試：網路連線錯誤的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_get.side_effect = requests.ConnectionError("Network error")

            with self.assertRaises(requests.ConnectionError):
                translator.do_translate("Test")

    def test_google_invalid_response_format(self):
        """測試：回應格式錯誤的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div>no translation here</div>'
            mock_get.return_value = mock_response

            with self.assertRaises(IndexError):
                translator.do_translate("Test")


class TestDeepLTranslator(unittest.TestCase):
    """測試 DeepLTranslator - 用 Mock 模擬 DeepL SDK"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        envs = {"DEEPL_AUTH_KEY": "fake_key"}
        translator = DeepLTranslator(
            lang_in="en", lang_out="zh", model=None, envs=envs
        )

        with patch.object(translator.client, 'translate_text') as mock_translate:
            mock_result = MagicMock()
            mock_result.text = "你好世界"
            mock_translate.return_value = mock_result

            result = translator.do_translate("Hello World")
            self.assertEqual(result, "你好世界")

            mock_translate.assert_called_once_with(
                "Hello World",
                target_lang="zh-Hans",
                source_lang="en"
            )

    def test_translate_calls_sdk_correctly(self):
        """測試：確認正確呼叫 DeepL SDK"""
        envs = {"DEEPL_AUTH_KEY": "fake_key"}
        translator = DeepLTranslator(
            lang_in="en", lang_out="zh-Hans", model=None, envs=envs
        )

        with patch.object(translator.client, 'translate_text') as mock_translate:
            mock_result = MagicMock()
            mock_result.text = "結果"
            mock_translate.return_value = mock_result

            translator.do_translate("Test")

            call_args = mock_translate.call_args
            self.assertEqual(call_args[0][0], "Test")
            self.assertEqual(call_args[1]['target_lang'], "zh-Hans")
            self.assertEqual(call_args[1]['source_lang'], "en")


class TestAnythingLLMTranslator(unittest.TestCase):
    """測試 AnythingLLMTranslator - 用 Mock 模擬 HTTP 請求"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        envs = {
            "AnythingLLM_URL": "http://localhost:3001/api/chat",
            "AnythingLLM_APIKEY": "fake_key"
        }
        translator = AnythingLLMTranslator(
            lang_in="en", lang_out="zh", model=None, envs=envs
        )

        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "textResponse": "你好世界"
            }
            mock_post.return_value = mock_response

            result = translator.do_translate("Hello World")
            self.assertEqual(result, "你好世界")
            self.assertTrue(mock_post.called)

    def test_translate_payload_format(self):
        """測試：payload 格式正確"""
        envs = {
            "AnythingLLM_URL": "http://localhost:3001/api/chat",
            "AnythingLLM_APIKEY": "fake_key"
        }
        translator = AnythingLLMTranslator(
            lang_in="en", lang_out="zh", model=None, envs=envs
        )

        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"textResponse": "結果"}
            mock_post.return_value = mock_response

            translator.do_translate("Test")

            call_args = mock_post.call_args
            self.assertEqual(call_args[0][0], "http://localhost:3001/api/chat")

            headers = call_args[1]['headers']
            self.assertIn("Authorization", headers)
            self.assertEqual(headers["Authorization"], "Bearer fake_key")
            self.assertEqual(call_args[1]['timeout'], 30)

    def test_translate_missing_textResponse(self):
        """測試：回應缺少 textResponse 的處理"""
        envs = {
            "AnythingLLM_URL": "http://localhost:3001/api/chat",
            "AnythingLLM_APIKEY": "fake_key"
        }
        translator = AnythingLLMTranslator(
            lang_in="en", lang_out="zh", model=None, envs=envs
        )

        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"error": "something wrong"}
            mock_post.return_value = mock_response

            result = translator.do_translate("Test")
            self.assertIsNone(result)


class TestOpenAITranslator(unittest.TestCase):
    """測試 OpenAITranslator - 基礎類別"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        envs = {
            "OPENAI_BASE_URL": "https://api.openai.com/v1",
            "OPENAI_API_KEY": "fake_key"
        }
        translator = OpenAITranslator(
            lang_in="en",
            lang_out="zh",
            model="gpt-3.5-turbo",
            envs=envs
        )

        with patch.object(translator.client.chat.completions, 'create') as mock_create:
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "你好世界"
            mock_create.return_value = mock_response

            result = translator.do_translate("Hello World")
            self.assertEqual(result, "你好世界")
            self.assertTrue(mock_create.called)

    def test_translate_empty_choices(self):
        """測試：回應中沒有 choices 的處理"""
        envs = {
            "OPENAI_BASE_URL": "https://api.openai.com/v1",
            "OPENAI_API_KEY": "fake_key"
        }
        translator = OpenAITranslator(
            lang_in="en",
            lang_out="zh",
            model="gpt-3.5-turbo",
            envs=envs
        )

        with patch.object(translator.client.chat.completions, 'create') as mock_create:
            mock_response = MagicMock()
            mock_response.choices = []
            mock_create.return_value = mock_response

            with self.assertRaises(ValueError):
                translator.do_translate("Test")


# ========== 小眾翻譯器測試 ==========

class TestOpenAIBasedTranslators(unittest.TestCase):
    """測試所有基於 OpenAI API 的翻譯器"""

    def setUp(self):
        """每個測試前初始化"""
        ConfigManager.clear()
        self.lang_in = "en"
        self.lang_out = "zh"
        self.model = "test-model"
        self.default_envs = {
            "OPENAI_API_KEY": "test-key",
            "OPENAI_BASE_URL": "https://test.url",
            "OPENAI_MODEL": "test-model"
        }

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_modelscope_translator_initialization(self, mock_openai, mock_init_db):
        """測試 ModelScopeTranslator 初始化"""
        translator = ModelScopeTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "modelscope")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_zhipu_translator_initialization(self, mock_openai, mock_init_db):
        """測試 ZhipuTranslator 初始化"""
        translator = ZhipuTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "zhipu")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_silicon_translator_initialization(self, mock_openai, mock_init_db):
        """測試 SiliconTranslator 初始化"""
        translator = SiliconTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "silicon")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_x302ai_translator_initialization(self, mock_openai, mock_init_db):
        """測試 X302AITranslator 初始化"""
        translator = X302AITranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "302ai")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_gemini_translator_initialization(self, mock_openai, mock_init_db):
        """測試 GeminiTranslator 初始化"""
        translator = GeminiTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "gemini")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_grok_translator_initialization(self, mock_openai, mock_init_db):
        """測試 GrokTranslator 初始化"""
        translator = GrokTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "grok")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_groq_translator_initialization(self, mock_openai, mock_init_db):
        """測試 GroqTranslator 初始化"""
        translator = GroqTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "groq")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_deepseek_translator_initialization(self, mock_openai, mock_init_db):
        """測試 DeepseekTranslator 初始化"""
        translator = DeepseekTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "deepseek")

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_qwenmt_translator_initialization(self, mock_openai, mock_init_db):
        """測試 QwenMtTranslator 初始化"""
        translator = QwenMtTranslator(
            lang_in=self.lang_in,
            lang_out=self.lang_out,
            model=self.model,
            envs=self.default_envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "qwen-mt")


class TestSpecialTranslators(unittest.TestCase):
    """測試特殊的翻譯器"""

    def setUp(self):
        """每個測試前初始化"""
        ConfigManager.clear()

    def test_xinference_translator_name(self):
        """測試 XinferenceTranslator 名稱"""
        self.assertEqual(XinferenceTranslator.name, "xinference")

    def test_azure_translator_name(self):
        """測試 AzureTranslator 名稱"""
        self.assertEqual(AzureTranslator.name, "azure")

    def test_tencent_translator_name(self):
        """測試 TencentTranslator 名稱"""
        self.assertEqual(TencentTranslator.name, "tencent")

    @patch('pdf2zh.cache.init_db')
    @patch('requests.post')
    def test_dify_translator_initialization(self, mock_post, mock_init_db):
        """測試 DifyTranslator 初始化"""
        envs = {
            "DIFY_BASE_URL": "https://test.url",
            "DIFY_API_KEY": "test-key"
        }
        translator = DifyTranslator(
            lang_in="en",
            lang_out="zh",
            model="",
            envs=envs,
            ignore_cache=True
        )
        self.assertEqual(translator.name, "dify")


class TestTranslatorEnvs(unittest.TestCase):
    """測試翻譯器的環境變數處理"""

    def setUp(self):
        """每個測試前初始化"""
        ConfigManager.clear()

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_set_envs_with_custom_values(self, mock_openai, mock_init_db):
        """測試自定義環境變數"""
        default_envs = {
            "OPENAI_API_KEY": "test-key",
            "OPENAI_BASE_URL": "https://test.url",
            "OPENAI_MODEL": "test-model"
        }
        translator = ModelScopeTranslator(
            lang_in="en",
            lang_out="zh",
            model="test-model",
            envs=default_envs,
            ignore_cache=True
        )

        custom_envs = {"OPENAI_API_KEY": "custom-key", "OPENAI_BASE_URL": "https://custom.url"}
        translator.set_envs(custom_envs)

        self.assertEqual(translator.envs["OPENAI_API_KEY"], "custom-key")
        self.assertEqual(translator.envs["OPENAI_BASE_URL"], "https://custom.url")


class TestTranslatorCacheImpact(unittest.TestCase):
    """測試影響快取的參數"""

    def setUp(self):
        """每個測試前初始化"""
        ConfigManager.clear()

    @patch('pdf2zh.cache.init_db')
    @patch('openai.OpenAI')
    def test_add_cache_impact_parameters(self, mock_openai, mock_init_db):
        """測試添加影響快取的參數"""
        default_envs = {
            "OPENAI_API_KEY": "test-key",
            "OPENAI_BASE_URL": "https://test.url",
            "OPENAI_MODEL": "test-model"
        }
        translator = SiliconTranslator(
            lang_in="en",
            lang_out="zh",
            model="test-model",
            envs=default_envs,
            ignore_cache=True
        )

        translator.add_cache_impact_parameters("temperature", 0.7)
        translator.add_cache_impact_parameters("top_p", 0.9)

        self.assertEqual(translator.cache.params["temperature"], 0.7)
        self.assertEqual(translator.cache.params["top_p"], 0.9)


# ========== 整合測試（需要真實 API，默認跳過）==========

@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION"),
    reason="整合測試需要設定 RUN_INTEGRATION=1 環境變數"
)
class TestGoogleTranslatorIntegration:
    """整合測試：真實呼叫 Google API"""

    def test_real_translation(self):
        """測試：真的呼叫 Google API 翻譯"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)
        result = translator.do_translate("Hello World")

        assert result is not None
        assert len(result) > 0
        print(f"翻譯結果：{result}")

    def test_real_emoji_translation(self):
        """測試：emoji 能不能真的翻譯"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)
        result = translator.do_translate("Hello👋World")

        assert result is not None
        assert len(result) > 0
        print(f"Emoji 翻譯結果：{result}")

    def test_real_max_length(self):
        """測試：超長文字的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)
        long_text = "Hello " * 1000

        result = translator.do_translate(long_text)
        assert result is not None
        print(f"長文翻譯結果長度：{len(result)}")


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION"),
    reason="整合測試需要設定 RUN_INTEGRATION=1 環境變數"
)
class TestBingTranslatorIntegration:
    """整合測試：真實呼叫 Bing API"""

    def test_real_translation(self):
        """測試：真的呼叫 Bing API 翻譯"""
        translator = BingTranslator(lang_in="en", lang_out="zh", model=None)
        result = translator.do_translate("Hello World")

        assert result is not None
        assert len(result) > 0
        print(f"Bing 翻譯結果：{result}")


if __name__ == "__main__":
    unittest.main()
