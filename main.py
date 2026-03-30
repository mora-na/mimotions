# -*- coding: utf8 -*-
import json
import math
import os
import random
import re
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

import pytz
import requests

from util.aes_help import decrypt_data, encrypt_data
import util.zepp_helper as zepp_helper


# 常量定义
SHANGHAI_TZ = pytz.timezone("Asia/Shanghai")
TIME_2130_MINUTES = 21 * 60 + 30
TOKEN_FILE = Path("encrypted_tokens.data")
ACCESS_TOKEN_PATTERN = re.compile(r"(?<=access=).*?(?=&)")
ERROR_CODE_PATTERN = re.compile(r"(?<=error=).*?(?=&)")

# 默认步数配置
DEFAULT_MIN_STEP = 18000
DEFAULT_MAX_STEP = 25000
DEFAULT_SLEEP_SECONDS = 5.0

def get_int_value_default(
    account: str,
    config: dict[str, Any],
    key: str,
    default: Union[int, str]
) -> int:
    """获取配置值并转为int，优先级：账号专属 > 根配置 > 默认值。

    Args:
        account: 账号标识
        config: 配置字典
        key: 配置键名
        default: 默认值

    Returns:
        转换后的整数值
    """
    # 1. 优先读取账号专属配置（STEP_RANGES）
    step_ranges = config.get("STEP_RANGES", {})
    if isinstance(step_ranges, dict) and account in step_ranges:
        account_config = step_ranges[account]
        if isinstance(account_config, dict) and key in account_config:
            return int(account_config[key])

    # 2. 读取根节点配置
    if key in config:
        return int(config[key])

    # 3. 所有配置都不存在，返回默认值
    return int(default)


def get_min_max_by_time(
    account: str,
    config: dict[str, Any],
    hour: Optional[int] = None,
    minute: Optional[int] = None
) -> tuple[int, int]:
    """根据当前时间和配置返回步数范围。

    时间分界点为21:30：
    - 21:30前：返回 (MIN, 中间值)
    - 21:30后：返回 (中间值, MAX)

    Args:
        account: 账号标识
        config: 配置字典
        hour: 指定小时（可选，默认使用当前时间）
        minute: 指定分钟（可选，默认使用当前时间）

    Returns:
        (最小步数, 最大步数) 元组
    """
    # 自动获取当前北京时间（未传时分时）
    if hour is None or minute is None:
        current_time = get_beijing_time()
        hour = hour or current_time.hour
        minute = minute or current_time.minute

    # 读取步数配置（优先账号专属）
    min_step = get_int_value_default(account, config, "MIN_STEP", DEFAULT_MIN_STEP)
    max_step = get_int_value_default(account, config, "MAX_STEP", DEFAULT_MAX_STEP)

    # 计算中间分界值
    mid_step = (min_step + max_step) // 2

    # 时间判断（21:30为分界点）
    current_total_min = hour * 60 + minute

    if current_total_min < TIME_2130_MINUTES:
        return min_step, mid_step
    return mid_step, max_step


def generate_fake_ip() -> str:
    """生成虚拟IP地址（国内IP段：223.64.0.0 - 223.117.255.255）。"""
    return f"223.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def desensitize_username(user: str) -> str:
    """对账号进行脱敏处理。

    Args:
        user: 原始账号

    Returns:
        脱敏后的账号
    """
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f"{user[:ln]}***{user[-ln:]}"
    return f"{user[:3]}****{user[-4:]}"


def get_beijing_time() -> datetime:
    """获取当前北京时间。"""
    return datetime.now(tz=SHANGHAI_TZ)


def format_now() -> str:
    """格式化当前时间为字符串（MM-DD HH:MM）。"""
    return get_beijing_time().strftime("%m-%d %H:%M")


def get_timestamp_ms() -> str:
    """获取当前时间戳（毫秒级）。"""
    return f"{int(get_beijing_time().timestamp() * 1000)}"


def extract_access_token(location: str) -> Optional[str]:
    """从location中提取access_token。

    Args:
        location: 包含access_token的字符串

    Returns:
        提取到的access_token，未找到返回None
    """
    match = ACCESS_TOKEN_PATTERN.search(location)
    return match.group(0) if match else None


def extract_error_code(location: str) -> Optional[str]:
    """从location中提取error_code。

    Args:
        location: 包含error_code的字符串

    Returns:
        提取到的error_code，未找到返回None
    """
    match = ERROR_CODE_PATTERN.search(location)
    return match.group(0) if match else None


def is_truthy(value: Any) -> bool:
    """判断值是否为真值。

    支持的 Truthy 值: True, 1, '1', 'true', 'yes', 'on'（不区分大小写）

    Args:
        value: 任意值

    Returns:
        是否为真值
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def send_serverchan_notification(
    sendkey: str,
    title: str,
    description: str = "",
    options: Optional[dict] = None
) -> dict:
    """发送Server酱推送通知。

    Args:
        sendkey: Server酱发送密钥
        title: 通知标题
        description: 通知内容
        options: 额外参数

    Returns:
        API响应结果

    Raises:
        ValueError: sendkey格式无效
        requests.RequestException: 请求异常
    """
    options = options or {}

    if sendkey.startswith("sctp"):
        match = re.fullmatch(r"sctp(\d+)t", sendkey)
        if not match:
            raise ValueError("Invalid sendkey format for sctp")
        url = f"https://{match.group(1)}.push.ft07.com/send/{sendkey}.send"
    else:
        url = f"https://sctapi.ftqq.com/{sendkey}.send"

    params = {
        "title": title,
        "desp": description,
        **options
    }
    headers = {"Content-Type": "application/json;charset=utf-8"}

    response = requests.post(url, json=params, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


class MiMotionRunner:
    """小米运动步数修改执行器。"""

    def __init__(self, username: str, password: str):
        """初始化执行器。

        Args:
            username: 小米账号（手机号或邮箱）
            password: 小米密码
        """
        self.user_id: Optional[str] = None
        self.device_id = str(uuid.uuid4())
        self.log_lines: list[str] = []
        self.invalid = False
        self.error = ""

        user = str(username).strip()
        pwd = str(password).strip()

        if not user or not pwd:
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            return

        self.password = pwd
        self.user = self._normalize_username(user)
        self.is_phone = self.user.startswith("+86")

    def _normalize_username(self, user: str) -> str:
        """标准化用户名格式。

        - 手机号自动添加+86前缀
        - 邮箱保持不变
        """
        if user.startswith("+86") or "@" in user:
            return user
        return f"+86{user}"

    @property
    def log_str(self) -> str:
        """获取合并的日志字符串。"""
        return "\n".join(self.log_lines)

    def _log(self, message: str) -> None:
        """添加日志记录。"""
        self.log_lines.append(message)

    def _try_refresh_from_cache(self, token_info: dict) -> Optional[str]:
        """尝试从缓存刷新app_token。"""
        app_token = token_info.get("app_token")
        if app_token:
            ok, _ = zepp_helper.check_app_token(app_token)
            if ok:
                self._log("使用加密保存的app_token")
                return app_token
            self._log(f"app_token失效，需重新获取 (上次: {token_info.get('app_token_time')})")
        return None

    def _try_refresh_from_login_token(self, token_info: dict) -> Optional[str]:
        """尝试使用login_token刷新app_token。"""
        login_token = token_info.get("login_token")
        if not login_token:
            return None

        app_token, _ = zepp_helper.grant_app_token(login_token)
        if app_token:
            self._log("使用login_token重新获取app_token成功")
            token_info["app_token"] = app_token
            token_info["app_token_time"] = get_timestamp_ms()
            return app_token
        self._log(f"login_token失效，需重新获取 (上次: {token_info.get('login_token_time')})")
        return None

    def _try_refresh_from_access_token(self, token_info: dict) -> Optional[str]:
        """尝试使用access_token刷新login_token和app_token。"""
        access_token = token_info.get("access_token")
        if not access_token:
            return None

        login_token, app_token, user_id, msg = zepp_helper.grant_login_tokens(
            access_token, self.device_id, self.is_phone
        )
        if login_token:
            self._log("使用access_token重新获取login_token成功")
            token_info["login_token"] = login_token
            token_info["app_token"] = app_token
            token_info["user_id"] = user_id
            current_time = get_timestamp_ms()
            token_info["login_token_time"] = current_time
            token_info["app_token_time"] = current_time
            self.user_id = user_id
            return app_token
        self._log(f"access_token已失效：{msg} (上次: {token_info.get('access_token_time')})")
        return None

    def _do_login(self) -> Optional[str]:
        """执行完整登录流程获取新token。"""
        access_token, msg = zepp_helper.login_access_token(self.user, self.password)
        if access_token is None:
            self._log(f"登录获取access_token失败：{msg}")
            return None

        login_token, app_token, user_id, msg = zepp_helper.grant_login_tokens(
            access_token, self.device_id, self.is_phone
        )
        if login_token is None:
            self._log(f"登录提取的access_token无效：{msg}")
            return None

        current_time = get_timestamp_ms()
        user_tokens[self.user] = {
            "access_token": access_token,
            "login_token": login_token,
            "app_token": app_token,
            "user_id": user_id,
            "access_token_time": current_time,
            "login_token_time": current_time,
            "app_token_time": current_time,
            "device_id": self.device_id,
        }
        return app_token

    def login(self) -> Optional[str]:
        """执行登录获取有效的app_token。

        Returns:
            有效的app_token，登录失败返回None
        """
        token_info = user_tokens.get(self.user)

        if token_info is not None:
            self.device_id = token_info.get("device_id") or self.device_id
            self.user_id = token_info.get("user_id")

            # 尝试各级token刷新
            for refresh_method in [
                self._try_refresh_from_cache,
                self._try_refresh_from_login_token,
                self._try_refresh_from_access_token,
            ]:
                token = refresh_method(token_info)
                if token:
                    return token

        # 缓存全部失效，执行完整登录
        return self._do_login()


    def login_and_post_step(self, min_step: int, max_step: int) -> tuple[str, bool]:
        """登录并提交步数。

        Args:
            min_step: 最小步数
            max_step: 最大步数

        Returns:
            (执行结果消息, 是否成功) 元组
        """
        if self.invalid:
            return "账号或密码配置有误", False

        app_token = self.login()
        if app_token is None:
            return "登录失败！", False

        step = random.randint(min_step, max_step)
        self._log(f"已设置为随机步数范围({min_step}~{max_step})，随机值：{step}")

        ok, msg = zepp_helper.post_fake_brand_data(str(step), app_token, self.user_id)
        return f"修改步数({step})[{msg}]", ok


def push_failed_results(
    exec_results: list[dict[str, Any]],
    summary: str,
    sendkey: Optional[str]
) -> None:
    """推送失败结果到Server酱。

    Args:
        exec_results: 执行结果列表
        summary: 执行摘要
        sendkey: Server酱发送密钥
    """
    if not sendkey:
        print("未配置SENDKEY，跳过Server酱推送")
        return

    failed_results = [r for r in exec_results if not r.get("success")]
    if not failed_results:
        print("本次执行无失败账号，跳过Server酱推送")
        return

    content_lines = [summary, "", "### 失败详情"]
    for result in failed_results:
        user = result["user"]
        msg = result["msg"]
        content_lines.extend([f"- 账号【{user}】", f"  失败原因：{msg}"])

    title = f"{format_now()} 步数任务存在失败"
    try:
        result = send_serverchan_notification(sendkey, title, "\n".join(content_lines))
        if result.get("code") == 0:
            print("Server酱推送成功")
        else:
            print(f"Server酱推送失败：{result}")
    except requests.exceptions.Timeout:
        print("Server酱推送超时")
    except requests.exceptions.ConnectionError:
        print("Server酱推送连接错误")
    except Exception as e:
        print(f"Server酱推送异常：{e}")


def run_single_account(
    total: int,
    idx: int,
    username: str,
    password: str,
    app_config: dict[str, Any]
) -> dict[str, Any]:
    """执行单个账号的步数修改任务。

    Args:
        total: 总账号数
        idx: 当前账号索引
        username: 用户名
        password: 密码
        app_config: 应用配置

    Returns:
        执行结果字典
    """
    idx_info = f"[{idx + 1}/{total}]" if idx is not None else ""
    runner = MiMotionRunner(username, password)

    log_header = f"[{format_now()}]\n{idx_info}账号：{desensitize_username(username)}\n"
    print(log_header, end="")

    try:
        min_step, max_step = get_min_max_by_time(username, app_config)
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
        print(f"{runner.log_str}\n{exec_msg}\n")
        return {"user": username, "success": success, "msg": exec_msg}
    except Exception:
        error_trace = traceback.format_exc()
        print(f"执行异常：{error_trace}\n")
        return {"user": username, "success": False, "msg": f"执行异常：{error_trace}"}


def run_account_task(task: tuple) -> dict[str, Any]:
    """适配多线程执行的任务包装器。"""
    total, idx, username, password, app_config = task
    return run_single_account(total, idx, username, password, app_config)


def execute(
    users_str: str,
    passwords_str: str,
    app_config: dict[str, Any],
    use_concurrent: bool,
    sleep_seconds: float,
    sendkey: Optional[str]
) -> None:
    """执行所有账号的步数修改任务。

    Args:
        users_str: 用户名字符串（#分隔）
        passwords_str: 密码字符串（#分隔）
        app_config: 应用配置
        use_concurrent: 是否并发执行
        sleep_seconds: 账号间执行间隔（秒）
        sendkey: Server酱发送密钥
    """
    user_list = users_str.split("#")
    passwd_list = passwords_str.split("#")

    if len(user_list) != len(passwd_list):
        print(f"账号数[{len(user_list)}]与密码数[{len(passwd_list)}]不匹配")
        exit(1)

    total = len(user_list)
    tasks = [
        (total, idx, user, pwd, app_config)
        for idx, (user, pwd) in enumerate(zip(user_list, passwd_list))
    ]

    if use_concurrent:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            exec_results = list(executor.map(run_account_task, tasks))
    else:
        exec_results = []
        for task in tasks:
            exec_results.append(run_account_task(task))
            if task[1] < total - 1:
                time.sleep(sleep_seconds)

    success_count = sum(1 for r in exec_results if r["success"])
    summary = f"\n执行账号总数：{total}，成功：{success_count}，失败：{total - success_count}"
    print(summary)
    push_failed_results(exec_results, summary, sendkey)


def prepare_user_tokens(aes_key: bytes) -> dict[str, Any]:
    """从加密文件加载用户token。

    Args:
        aes_key: AES加密密钥

    Returns:
        用户token字典
    """
    if not TOKEN_FILE.exists():
        return {}

    try:
        data = TOKEN_FILE.read_bytes()
        decrypted = decrypt_data(data, aes_key, None)
        return json.loads(decrypted.decode("utf-8", errors="strict"))
    except Exception:
        print("密钥不正确或加密内容损坏，放弃token缓存")
        return {}


def persist_user_tokens(aes_key: bytes, tokens: dict[str, Any]) -> None:
    """保存用户token到加密文件。

    Args:
        aes_key: AES加密密钥
        tokens: 用户token字典
    """
    json_str = json.dumps(tokens, ensure_ascii=False)
    cipher_data = encrypt_data(json_str.encode("utf-8"), aes_key, None)
    TOKEN_FILE.write_bytes(cipher_data)

def load_config() -> tuple[dict[str, Any], bytes, bool]:
    """加载应用配置。

    Returns:
        (配置字典, AES密钥, 是否支持加密) 元组
    """
    # 检查CONFIG环境变量
    config_json = os.environ.get("CONFIG")
    if not config_json:
        print("未配置CONFIG变量，无法执行")
        exit(1)

    try:
        config = json.loads(config_json)
    except json.JSONDecodeError:
        print("CONFIG格式不正确，请使用标准JSON格式（双引号包裹字段和值）")
        traceback.print_exc()
        exit(1)

    # 检查账号密码配置
    if not config.get("USER") or not config.get("PWD"):
        print("未正确配置账号密码，无法执行")
        exit(1)

    # 初始化AES加密
    encrypt_support = False
    aes_key: bytes = b""
    aes_key_str = os.environ.get("AES_KEY", "")
    if aes_key_str:
        key_bytes = aes_key_str.encode("utf-8")
        if len(key_bytes) == 16:
            encrypt_support = True
            aes_key = key_bytes
        else:
            print("AES_KEY长度不为16，无法使用加密保存功能")

    return config, aes_key, encrypt_support


def main() -> None:
    """程序入口。"""
    global encrypt_support, user_tokens

    config, aes_key, encrypt_support = load_config()
    user_tokens = prepare_user_tokens(aes_key) if encrypt_support else {}

    # 提取配置
    sendkey = os.environ.get("SENDKEY", "")
    sleep_seconds = float(config.get("SLEEP_GAP") or DEFAULT_SLEEP_SECONDS)
    use_concurrent = is_truthy(config.get("USE_CONCURRENT"))

    if not use_concurrent:
        print(f"多账号执行间隔：{sleep_seconds}秒")

    # 执行
    execute(
        users_str=config["USER"],
        passwords_str=config["PWD"],
        app_config=config,
        use_concurrent=use_concurrent,
        sleep_seconds=sleep_seconds,
        sendkey=sendkey,
    )

    # 保存token
    if encrypt_support:
        persist_user_tokens(aes_key, user_tokens)


if __name__ == "__main__":
    # 全局变量
    encrypt_support: bool = False
    user_tokens: dict[str, Any] = {}

    main()
