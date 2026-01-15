#!/usr/bin/env python3
import json
import requests
import threading
import time
import asyncio
import aiohttp

from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

# --- Config AES ---
key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

app = Flask(__name__)

# --- Global state ---
accounts_data = {}           # dict: { uid: password }
account_index = 0
accounts_lock = threading.Lock()

tokens = {}                  # dict: { token_str: usage_count }
tokens_lock = threading.Lock()

used_uids = {}               # dict: { uid: date_obj }
uids_lock = threading.Lock()

demo = False               # special token refreshed separately

api_keys = {
    "ngocduc": {"exp": "30/07/2095", "remain": 999, "max_remain": 999, "last_reset": None}
}

# --- Helpers / API key check ---
def is_key_valid(key):
    if key not in api_keys:
        return None
    expiration_date = datetime.strptime(api_keys[key]["exp"], "%d/%m/%Y")
    if datetime.utcnow() > expiration_date:
        return False
    current_date = datetime.utcnow().date()
    if api_keys[key]["remain"] <= 0:
        return False
    if api_keys[key].get("last_reset") != current_date:
        api_keys[key]["remain"] = api_keys[key]["max_remain"]
        api_keys[key]["last_reset"] = current_date
    return api_keys[key]["remain"] > 0

# --- Accounts load / iterator ---
def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except (FileNotFoundError, json.JSONDecodeError):
        accounts_data = {}
        print("No account.json or parse error - accounts_data empty")

def get_next_accounts(num=500):
    global account_index, accounts_data
    with accounts_lock:
        if not accounts_data:
            load_accounts()
        if not accounts_data:
            return []

        uids = list(accounts_data.keys())
        selected_accounts = []

        for i in range(min(num, len(uids))):
            if account_index >= len(uids):
                account_index = 0
            uid = uids[account_index]
            password = accounts_data[uid]
            selected_accounts.append((uid, password))
            account_index += 1

        return selected_accounts

# --- Protobuf helpers (kept as in original) ---
def Encrypt(number):
    number = int(number)
    if number < 0:
        return False
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    return Encrypt(field_header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return Encrypt(field_header) + Encrypt(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    return packet

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex_str):
    try:
        return json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False)
    except Exception:
        return "{}"

def encrypt_api(hex_str):
    try:
        plain_text = bytes.fromhex(hex_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception:
        return ""

# --- get_token: call new API and only look for "token" key ---
async def get_token(acc, session):
    """
    acc: either "uid:password" string or (uid, password) tuple/list
    session: aiohttp.ClientSession
    Trả về token (str) hoặc None.
    Chỉ tìm đúng key 'token' (đệ quy trong dict/list), in debug.
    """
    try:
        # --- tách uid/password ---
        if isinstance(acc, (list, tuple)):
            uid, password = acc[0], acc[1]
        elif isinstance(acc, str):
            if ":" in acc:
                uid, password = acc.split(":", 1)
            else:
                uid, password = acc, ""
        else:
            return None

        uid = str(uid).strip()
        password = str(password).strip()
        if not uid:
            return None

        url = f"https://ngocduc-api.vercel.app/token?uid={uid}&password={password}"
        async with session.get(url) as response:
            text = await response.text()

            # Debug prints
            print("=" * 60)
            print(f"[get_token] UID: {uid}")
            print(f"[get_token] STATUS: {response.status}")
            print(f"[get_token] RESPONSE (preview): {text[:600]}")

            if response.status not in (200, 201):
                print(f"[get_token] ❌ HTTP {response.status} for UID {uid}")
                return None

            # parse JSON
            try:
                data = json.loads(text)
            except Exception as e:
                print(f"[get_token] ❌ JSON parse error: {e}")
                return None

            # pretty-print a bit
            try:
                pretty = json.dumps(data, ensure_ascii=False)
                print(f"[get_token] PARSED JSON (preview): {pretty[:1000]}")
            except Exception:
                pass

            # --- đệ quy tìm key 'token' trong dict/list ---
            def find_token_only(obj, path="root"):
                if isinstance(obj, dict):
                    # check direct key first
                    if "token" in obj and isinstance(obj["token"], str) and obj["token"]:
                        return obj["token"], f"{path}.token"
                    # else recurse
                    for k, v in obj.items():
                        found, found_path = find_token_only(v, f"{path}.{k}")
                        if found:
                            return found, found_path
                    return None, None
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        found, found_path = find_token_only(item, f"{path}[{i}]")
                        if found:
                            return found, found_path
                    return None, None
                else:
                    return None, None

            token, token_path = find_token_only(data, "root")
            if token:
                print(f"[get_token] ✅ token found at {token_path}: {token[:80]}...")
                return token

            print(f"[get_token] ⚠️ 'token' key not found in response for UID {uid}")
            return None

    except Exception as e:
        print(f"[get_token] Exception: {e}")
        return None

# --- token management tasks ---
async def refresh_tokens():
    global tokens
    try:
        accounts = get_next_accounts(115)
        if accounts:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks)
                valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
                with tokens_lock:
                    tokens = {token: 0 for token in valid_tokens}
    except Exception as e:
        print(f"[refresh_tokens] Exception: {e}")
        with tokens_lock:
            tokens = {}
    # schedule next run
    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
    global tokens
    tokens_to_remove = []
    with tokens_lock:
        tokens_to_remove = [token for token, count in tokens.items() if count >= 27]
    if not tokens_to_remove:
        return
    accounts = get_next_accounts(len(tokens_to_remove) + 5)
    if accounts:
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
                valid_new_tokens = [token for token in new_tokens if isinstance(token, str) and token]

                with tokens_lock:
                    for old_token in tokens_to_remove:
                        if old_token in tokens:
                            del tokens[old_token]
                    for new_token in valid_new_tokens:
                        tokens[new_token] = 0
        except Exception as e:
            print(f"[clean_and_replace_tokens] Exception: {e}")
            with tokens_lock:
                for old_token in tokens_to_remove:
                    if old_token in tokens:
                        del tokens[old_token]

async def generate_additional_tokens(needed_tokens):
    try:
        accounts = get_next_accounts(needed_tokens + 10)
        if not accounts:
            return []
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
            new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
            valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
            with tokens_lock:
                for token in valid_tokens:
                    tokens[token] = 0
            return valid_tokens
    except Exception as e:
        print(f"[generate_additional_tokens] Exception: {e}")
        return []

async def refresh_token():
    global demo
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            demo = await get_token("4366520774:PHUCESIGNS-PQ8ODNQF5-PHUC", s)
    except Exception as e:
        print(f"[refresh_token] Exception: {e}")
    threading.Timer(13500, lambda: asyncio.run(refresh_token())).start()

# --- API calls to target service ---
async def LikesProfile(payload, session, token):
    try:
        url = "https://clientbp.ggpolarbear.com/LikeProfile"
        headers = {
            "ReleaseVersion": "OB52",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "Host": "clientbp.ggpolarbear.com"
        }
        async with session.post(url, headers=headers, data=payload, timeout=10) as res:
            return res.status == 200
    except Exception:
        return False

async def GetPlayerPersonalShow(payload, session):
    global demo
    try:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        headers = {
            "ReleaseVersion": "OB52",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {demo}",
            "Host": "clientbp.ggpolarbear.com"
        }
        async with session.post(url, headers=headers, data=payload) as res:
            if res.status == 200:
                r = await res.read()
                return json.loads(protobuf_dec(r.hex()))
            return None
    except Exception:
        return None

def add_token_usage(_tokens):
    with tokens_lock:
        for token in _tokens:
            if token in tokens:
                tokens[token] += 1

# --- Core sendLikes logic ---
async def sendLikes(uid):
    global used_uids, tokens
    today = datetime.now().date()
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    with tokens_lock:
        available_tokens = {k: v for k, v in tokens.items() if v < 27}
        token_list = list(available_tokens.keys())

    if len(token_list) < 115:
        needed_tokens = 115 - len(token_list)
        new_tokens = await generate_additional_tokens(needed_tokens)
        with tokens_lock:
            available_tokens = {k: v for k, v in tokens.items() if v < 27}
            token_list = list(available_tokens.keys())

        if len(token_list) < 1:
            return {"message": "{}".format(len(token_list))}, 200

    _tokens = token_list[:115]
    packet = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted_packet = encrypt_api(packet)
    if not encrypted_packet:
        return "null", 201
    payload = bytes.fromhex(encrypted_packet)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        InfoBefore = await GetPlayerPersonalShow(payload, session)
        if not InfoBefore or "1" not in InfoBefore or "21" not in InfoBefore["1"]:
            return {"Failse": "Account does not exist"}, 200

        LikesBefore = int(InfoBefore["1"]["21"])
        start_time = time.time()

        # create tasks using the selected tokens _tokens
        tasks = [LikesProfile(payload, session, token) for token in _tokens]
        await asyncio.gather(*tasks, return_exceptions=True)

        with uids_lock:
            used_uids[uid] = today

        InfoAfter = await GetPlayerPersonalShow(payload, session)
        if not InfoAfter or "1" not in InfoAfter or "21" not in InfoAfter["1"]:
            return "null", 201

        LikesAfter = int(InfoAfter["1"]["21"])
        LikesAdded = LikesAfter - LikesBefore

        add_token_usage(_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if LikesAdded <= 0:
            return {"Failse": "Account Id '{}' with name '{}' has reached max likes today, try again tomorrow !".format(InfoBefore["1"]["1"], InfoBefore["1"]["3"])}, 200

        end_time = time.time()
        return {
            "result": {
                "User Info": {
                    "Account UID": InfoBefore["1"]["1"],
                    "Account Name": InfoBefore["1"]["3"],
                    "Account Region": InfoBefore["1"]["5"],
                    "Account Level": InfoBefore["1"]["6"],
                    "Account Likes": InfoBefore["1"]["21"]
                },
                "Likes Info": {
                    "Likes Before": LikesBefore,
                    "Likes After": LikesBefore + LikesAdded,
                    "Likes Added": LikesAdded,
                    "Likes start of day": max(0, LikesBefore + LikesAdded - 250),
                },
                "API": {
                    "speeds": "{:.1f}s".format(end_time - start_time),
                    "Success": True,
                }
            }
        }, 200

# --- Reset logic ---
def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    next_reset = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    delta_seconds = (next_reset - now).total_seconds()
    threading.Timer(delta_seconds, lambda: [reset_uids(), schedule_reset()]).start()

# --- Flask route ---
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")
    if is_key_valid(key) is None:
        return jsonify({"message": "key not found, To buy key contact tg @Convitduc1"}), 200
    if not uid:
        return 'UID missing!'
    try:
        uid = str(uid).strip()
    except:
        return '?'
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(sendLikes(uid))
        loop.close()
        return jsonify(result[0]), result[1]
    except Exception as e:
        print(f"[FF_LIKES] Exception: {e}")
        return jsonify({"error": str(e)}), 500

# --- Main ---
if __name__ == "__main__":
    load_accounts()

    def background_tasks():
        # start token refreshers in background threads/tasks
        try:
            asyncio.run(refresh_tokens())
        except Exception as e:
            print(f"[background_tasks] refresh_tokens exception: {e}")
        try:
            asyncio.run(refresh_token())
        except Exception as e:
            print(f"[background_tasks] refresh_token exception: {e}")

    threading.Thread(target=background_tasks, daemon=True).start()
    schedule_reset()
    app.run(host="0.0.0.0", port=2026, threaded=True)