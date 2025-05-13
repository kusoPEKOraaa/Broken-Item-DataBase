import os
import base64
import requests
import hmac
import hashlib
from datetime import datetime, timezone
from urllib.parse import quote

class VolcEngineAPI:
    def __init__(self, access_key, secret_key, region="cn-north-1", service="cv"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service

    def _get_utc_time(self):
        """获取UTC时间(ISO 8601格式)"""
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    def _get_short_date(self):
        """获取短日期(YYYYMMDD)"""
        return datetime.now(timezone.utc).strftime("%Y%m%d")

    def _sign(self, key, msg):
        """HMAC-SHA256签名"""
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _get_signature_key(self):
        """生成签名密钥"""
        k_date = self._sign(("VOLC" + self.secret_key).encode('utf-8'), self._get_short_date())
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, self.service)
        k_signing = self._sign(k_service, "request")
        return k_signing

    def _calculate_signature(self, signed_headers, canonical_request):
        """计算签名"""
        signing_key = self._get_signature_key()
        string_to_sign = f"HMAC-SHA256\n{self._get_utc_time()}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    def call_seededit_api(
        self,
        image_data,
        prompt,
        negative_prompt="",
        seed=-1,
        scale=0.5,
        return_url=True
    ):
        """
        调用指令编辑API(SeedEdit)
        
        参数:
        - image_data: 图片Base64或URL列表
        - prompt: 编辑指令(如"改成漫画风格")
        - negative_prompt: 负面指令(可选)
        - seed: 随机种子(默认-1)
        - scale: 编辑强度(0-1,默认0.5)
        - return_url: 是否返回URL(默认True)
        """
        # 接口配置
        endpoint = "https://visual.volcengineapi.com"
        action = "CVProcess"
        version = "2022-08-31"
        
        # 构造请求URL
        url = f"{endpoint}?Action={action}&Version={version}"
        
        # 准备签名参数
        x_date = self._get_utc_time()
        signed_headers = "content-type;host;x-content-sha256;x-date"
        
        # 对空请求体使用特定哈希值
        empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        # 构造规范请求
        canonical_headers = (
            f"content-type:application/json\n"
            f"host:visual.volcengineapi.com\n"
            f"x-content-sha256:{empty_payload_hash}\n"
            f"x-date:{x_date}\n"
        )
        
        canonical_request = (
            f"POST\n"
            f"/\n"
            f"\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{empty_payload_hash}"
        )
        
        # 计算签名
        signature = self._calculate_signature(signed_headers, canonical_request)
        
        # 构造Authorization头
        credential = f"{self.access_key}/{self._get_short_date()}/{self.region}/{self.service}/request"
        authorization = (
            f"HMAC-SHA256 Credential={credential}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        
        # 请求头
        headers = {
            "Content-Type": "application/json",
            "X-Date": x_date,
            "X-Content-Sha256": empty_payload_hash,
            "Authorization": authorization
        }
        
        # 请求体
        payload = {
            "req_key": "byteedit_v2.0",
            "prompt": prompt,
            "negative_prompt": negative_prompt,
            "seed": seed,
            "scale": scale,
            "return_url": return_url,
            "logo_info": {"add_logo": False}
        }
        
        # 设置图片参数
        if isinstance(image_data, str):
            payload["binary_data_base64"] = [image_data]
        elif isinstance(image_data, list):
            payload["image_urls"] = image_data
        else:
            raise ValueError("image_data应为Base64字符串或图片URL列表")

        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API调用失败: {e}")
            return None

# 使用示例
if __name__ == "__main__":
    # 替换为你的火山引擎密钥
    ACCESS_KEY = "AKLTNzJhZWRlNzNmYTk4NDJjZjk4M2NjNzVlZmYyYjE4YmY"
    SECRET_KEY = "TjJVNFlqSmpOVGRrTURJNE5EZ3haV0V3TkROak5USTRNV1V6TWpjd01XTQ=="
    
    # 初始化API客户端
    volc_api = VolcEngineAPI(ACCESS_KEY, SECRET_KEY)
    
    # 示例1：使用本地图片
    def image_to_base64(image_path):
        """读取图片并转为Base64"""
        with open(image_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    
    image_path = r"F:\Broken-Item-DataBase\broken-image\001_tb.jpg"
    base64_image = image_to_base64(image_path)
    
    # 调用API
    result = volc_api.call_seededit_api(
        image_data=base64_image,
        prompt="把破损的物品复原",
        scale=0.7
    )
    
    # 处理结果
    if result and result.get("code") == 10000:
        print("编辑成功！")
        if "image_urls" in result.get("data", {}):
            print("结果图片URL:", result["data"]["image_urls"][0])
        if "binary_data_base64" in result.get("data", {}):
            with open("output.jpg", "wb") as f:
                f.write(base64.b64decode(result["data"]["binary_data_base64"][0]))
            print("结果图片已保存为output.jpg")
    else:
        print("编辑失败:", result)