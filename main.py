from flask import Flask
import flask
import requests

app = Flask(__name__)
@app.route("/")
def hello():
    import json
    import time
    from cryptor import DingTalkCrypto
    token = "123456"
    a = DingTalkCrypto(
        key="***", 
        encodingAesKey="**")
    content = flask.request.get_json()["encrypt"]
    payload = json.loads(a.decrypt(content))
    typ = payload.get("EventType")
    print(payload)

    encode_aes_key = '***'
    din_corpid = '***'
    # 调用上面的工具类
    dtc = DingTalkCrypto(encode_aes_key, din_corpid)
    # 加密
    encrypt = dtc.encrypt('success') # 加密数据
    timestamp = str(int(round(time.time()))) # 时间戳 (秒)
    nonce = dtc.generateRandomKey(8)  # 随机字符串
    # 生成签名
    signature = dtc.generateSignature(nonce, timestamp, token, encrypt)
    # 构造返回数据
    new_data = {
        'data': {
            'msg_signature': signature,
            'timeStamp': timestamp,
            'nonce': nonce,
            'encrypt': encrypt
        }
    }
    return flask.jsonify(new_data)

if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=80)
    key = "***"
    secret = "****"
    url = f"https://oapi.dingtalk.com/gettoken?appkey={key}&appsecret={secret}"
    response = requests.get(url)
    access_token = response.json().get("access_token")
    url_register = f"https://oapi.dingtalk.com/call_back/register_call_back?access_token={access_token}"
    response = requests.post(url_register, json={
        "call_back_tag": ["user_add_org", "user_modify_org", "user_leave_org"],
        "token": "123456",
        "aes_key": "***",
        "url":"http://***/home"
    })
    print(response.json())