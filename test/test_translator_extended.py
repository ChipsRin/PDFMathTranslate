import unittest
from unittest.mock import patch, MagicMock
import requests
import os

from pdf2zh.translator import (
    GoogleTranslator,
    BingTranslator,
    DeepLTranslator,
    AnythingLLMTranslator,
    OpenAITranslator
)


class TestGoogleTranslator(unittest.TestCase):
    """測試 GoogleTranslator - 用 Mock 模擬 HTTP 請求"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        # 建立翻譯器
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        # Mock HTTP 請求
        with patch.object(translator.session, 'get') as mock_get:
            # 設定 Mock 的回應
            mock_response = MagicMock()
            mock_response.status_code = 200
            # 模擬 Google 回傳的 HTML（包含翻譯結果）
            mock_response.text = '<div class="result-container">你好世界</div>'
            mock_get.return_value = mock_response

            # 執行翻譯
            result = translator.do_translate("Hello World")

            # 驗證：翻譯結果正確
            self.assertEqual(result, "你好世界")

            # 驗證：HTTP 請求有被呼叫
            mock_get.assert_called_once()

    def test_translate_max_length(self):
        """測試：超過 5000 字元會被截斷"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '<div class="result-container">結果</div>'
            mock_get.return_value = mock_response

            # 測試超長文字（6000 字元）
            long_text = "a" * 6000
            translator.do_translate(long_text)

            # 取得實際送出的請求參數
            call_args = mock_get.call_args
            actual_text = call_args[1]['params']['q']

            # 驗證：文字被截斷成 5000 字元
            self.assertEqual(len(actual_text), 5000)

    def test_translate_html_unescape(self):
        """測試：HTML 特殊字元能正確轉換"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            # &amp; 應該被轉成 &
            mock_response.text = '<div class="result-container">A &amp; B</div>'
            mock_get.return_value = mock_response

            result = translator.do_translate("A & B")

            # 驗證：&amp; 被正確轉換成 &
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

            # 驗證：400 錯誤時回傳特定訊息
            self.assertEqual(result, "IRREPARABLE TRANSLATION ERROR")

    def test_translate_with_special_characters(self):
        """測試：特殊字元的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            # 包含中文、emoji、換行符
            mock_response.text = '<div class="result-container">你好👋\n世界</div>'
            mock_get.return_value = mock_response

            result = translator.do_translate("Hello👋\nWorld")

            # 驗證：特殊字元被正確處理（\n 等控制字元會被移除）
            self.assertIsNotNone(result)


class TestBingTranslator(unittest.TestCase):
    """測試 BingTranslator - 測試兩階段請求流程"""

    def test_translate_success(self):
        """測試：正常翻譯流程（包含 token 取得）"""
        translator = BingTranslator(lang_in="en", lang_out="zh", model=None)

        # Mock 第一階段：取得 token
        with patch.object(translator.session, 'get') as mock_get, \
             patch.object(translator.session, 'post') as mock_post:

            # 設定第一階段的回應（取得 token）
            mock_get_response = MagicMock()
            mock_get_response.url = "https://www.bing.com/translator"
            mock_get_response.text = '''
                "ig":"ABC123"
                data-iid="translator.5678"
                params_AbusePreventionHelper = [123,"token_value",
            '''
            mock_get.return_value = mock_get_response

            # 設定第二階段的回應（翻譯）
            mock_post_response = MagicMock()
            mock_post_response.json.return_value = [
                {"translations": [{"text": "你好世界"}]}
            ]
            mock_post.return_value = mock_post_response

            # 執行翻譯
            result = translator.do_translate("Hello World")

            # 驗證：翻譯結果正確
            self.assertEqual(result, "你好世界")

            # 驗證：兩階段請求都有被呼叫
            self.assertTrue(mock_get.called, "第一階段 GET 請求應該被呼叫")
            self.assertTrue(mock_post.called, "第二階段 POST 請求應該被呼叫")

    def test_translate_max_length(self):
        """測試：超過 1000 字元會被截斷"""
        translator = BingTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get, \
             patch.object(translator.session, 'post') as mock_post:

            # Mock token 取得
            mock_get_response = MagicMock()
            mock_get_response.url = "https://www.bing.com/translator"
            mock_get_response.text = '''
                "ig":"ABC123"
                data-iid="translator.5678"
                params_AbusePreventionHelper = [123,"token_value",
            '''
            mock_get.return_value = mock_get_response

            # Mock 翻譯回應
            mock_post_response = MagicMock()
            mock_post_response.json.return_value = [
                {"translations": [{"text": "結果"}]}
            ]
            mock_post.return_value = mock_post_response

            # 測試超長文字（1500 字元）
            long_text = "a" * 1500
            translator.do_translate(long_text)

            # 取得 POST 請求的 data
            call_args = mock_post.call_args
            actual_text = call_args[1]['data']['text']

            # 驗證：文字被截斷成 1000 字元
            self.assertEqual(len(actual_text), 1000)


class TestTranslatorErrorHandling(unittest.TestCase):
    """測試翻譯器的錯誤處理"""

    def test_google_http_timeout(self):
        """測試：HTTP timeout 的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            # 模擬 timeout 錯誤
            mock_get.side_effect = requests.Timeout("Connection timeout")

            # 驗證：應該拋出 Timeout 例外
            with self.assertRaises(requests.Timeout):
                translator.do_translate("Test")

    def test_google_connection_error(self):
        """測試：網路連線錯誤的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            # 模擬連線錯誤
            mock_get.side_effect = requests.ConnectionError("Network error")

            # 驗證：應該拋出 ConnectionError
            with self.assertRaises(requests.ConnectionError):
                translator.do_translate("Test")

    def test_google_invalid_response_format(self):
        """測試：回應格式錯誤的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        with patch.object(translator.session, 'get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            # 錯誤的 HTML 格式（regex 找不到結果）
            mock_response.text = '<div>no translation here</div>'
            mock_get.return_value = mock_response

            # 驗證：應該拋出 IndexError（regex 找不到匹配）
            with self.assertRaises(IndexError):
                translator.do_translate("Test")


class TestDeepLTranslator(unittest.TestCase):
    """測試 DeepLTranslator - 用 Mock 模擬 DeepL SDK"""

    def test_translate_success(self):
        """測試：正常翻譯流程"""
        # 建立翻譯器（需要提供 API Key）
        envs = {"DEEPL_AUTH_KEY": "fake_key"}
        translator = DeepLTranslator(
            lang_in="en", lang_out="zh", model=None, envs=envs
        )

        # Mock DeepL client 的 translate_text 方法
        with patch.object(translator.client, 'translate_text') as mock_translate:
            # 設定 Mock 的回應
            mock_result = MagicMock()
            mock_result.text = "你好世界"
            mock_translate.return_value = mock_result

            # 執行翻譯
            result = translator.do_translate("Hello World")

            # 驗證：翻譯結果正確
            self.assertEqual(result, "你好世界")

            # 驗證：translate_text 有被呼叫，且參數正確
            # 注意：DeepL 會把 "zh" 轉換成 "zh-Hans"（通過 lang_map）
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

            # 驗證：呼叫參數正確（包含 target_lang 和 source_lang）
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

        # Mock requests.post
        with patch('requests.post') as mock_post:
            # 設定 Mock 的回應
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "textResponse": "你好世界"
            }
            mock_post.return_value = mock_response

            # 執行翻譯
            result = translator.do_translate("Hello World")

            # 驗證：翻譯結果正確
            self.assertEqual(result, "你好世界")

            # 驗證：HTTP 請求有被呼叫
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

            # 取得實際的 POST 請求
            call_args = mock_post.call_args

            # 驗證：URL 正確
            self.assertEqual(call_args[0][0], "http://localhost:3001/api/chat")

            # 驗證：headers 包含 Authorization
            headers = call_args[1]['headers']
            self.assertIn("Authorization", headers)
            self.assertEqual(headers["Authorization"], "Bearer fake_key")

            # 驗證：timeout 有設定
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
            # 回應中沒有 textResponse key
            mock_response = MagicMock()
            mock_response.json.return_value = {"error": "something wrong"}
            mock_post.return_value = mock_response

            # 執行翻譯
            result = translator.do_translate("Test")

            # 驗證：回傳 None（因為沒有 textResponse）
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

        # Mock OpenAI client 的 chat.completions.create 方法
        with patch.object(translator.client.chat.completions, 'create') as mock_create:
            # 設定 Mock 的回應
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "你好世界"
            mock_create.return_value = mock_response

            # 執行翻譯
            result = translator.do_translate("Hello World")

            # 驗證：翻譯結果正確
            self.assertEqual(result, "你好世界")

            # 驗證：create 有被呼叫
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
            # 回應中沒有 choices
            mock_response = MagicMock()
            mock_response.choices = []
            mock_create.return_value = mock_response

            # 驗證：應該拋出 ValueError
            with self.assertRaises(ValueError):
                translator.do_translate("Test")


# ========== 整合測試（需要真實 API，默認跳過）==========

import pytest


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

        # 真的呼叫 Google API
        result = translator.do_translate("Hello World")

        # 驗證：有成功回傳結果
        assert result is not None
        assert len(result) > 0
        # 不驗證確切內容，因為 Google 可能改翻譯
        print(f"翻譯結果：{result}")

    def test_real_emoji_translation(self):
        """測試：emoji 能不能真的翻譯"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        result = translator.do_translate("Hello👋World")

        # 驗證：有回傳結果
        assert result is not None
        assert len(result) > 0
        print(f"Emoji 翻譯結果：{result}")

    def test_real_max_length(self):
        """測試：超長文字的處理"""
        translator = GoogleTranslator(lang_in="en", lang_out="zh", model=None)

        # 6000 字元（超過 5000 限制）
        long_text = "Hello " * 1000

        result = translator.do_translate(long_text)

        # 驗證：有回傳結果（應該被截斷）
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

        # 驗證：有成功回傳結果
        assert result is not None
        assert len(result) > 0
        print(f"Bing 翻譯結果：{result}")


if __name__ == "__main__":
    unittest.main()
