# study-api-security

## Introduction

`study-api-security` focus on how to ensure the api security when it exposes to the public network.

## More About Sign

**Sign** is the signature of the request. It joins some request information and other message can be identified. Then it is encrypted using `md5` or other encryption algorithm and follows the request as a query string or payload.

```JavaScript
// index.html:76

// The app id is unique for every request client.
// The secret is used to sign to ensure the security of the request.
// 
// Usually, the app id and secret is applied in other api.
// To acquire the security of the secret, using `https` is an idea.
const appId = "IPAD-L3GZ89D";
const secret = "123456";

apiBtn.addEventListener("click", async function() {
    // get current timestamp
    let ts = (new Date()).getTime();

    // sort all payload according to the `Unicode`
    // you can add other payload such as salt to futher ensure the security
    let payload = `appId${appId}secret${secret}ts${ts}`;

    // use md5 to get digest of the payload
    let sign = SparkMD5.hash(payload);

    // ...
}
```

After receiving the request, the server is will calculate the *sign* again and compare with the request sign. If the sign is different, the request may be falsified. So the server will deny to handle the request.

```Golang
// main.go:128

str := fmt.Sprintf("appId%vsecret%vts%d", appId, secret, reqTs)
serveSign := fmt.Sprintf("%x", md5.Sum([]byte(str)))

if reqSign != serveSign {
    writeBack(w, CodeHandleFail, "sign not correct", http.StatusBadRequest)
    return
}

// ...
```

## More About Token

**Token** is the identification of every request. The interface can not be called without the token. It is similar to the `cookie` and `session`.

**Token** can be sorted by *API Token* and *User Token*.

### API Token

*API Token* enables you to access any interfaces without login.

To get *API Token*, the client needs two important keys. That is **appid** and **app secret**.

The **appid** is the client unique id. It is applied in advance through the either specific interface or off-line.

The **app secret** is one of the *sign* components. It should be stored carefully in the client.

Usually, **https** can guarantee the **appid** and **app secret**. But it doesn't' mean to expose the both keys directly in page.

The more details about *API Token* can see on [main.go](https://github.com/ChenYuTong10/study-api/blob/master/main.go#L81).

### User Token

*User Token* enables you to visit the interfaces needed login.
    
To get *User Token*, you need to send the *username* and *password* to the server like login operation.

The more details about *User Token* can see on [main.go](https://github.com/ChenYuTong10/study-api/blob/master/main.go#L162).

## More About Other

### Replay Attack

*Replay Attack* is one of common attacks. The attacker can call specific interface through capturing a request package all the times. So we can add a timestamp to defend the attack. If the difference of timestamp between the request and server is greater than the threshold, we can deny to provide the service.

What'more, the attacker can not modify the timestamp due to the *sign*. If the timestamp in the request is modified, the *sign* will change and the request will be rejected.

```Golang
// main.go:238

// check the request time
reqTs, err := strconv.ParseInt(q.Get("ts"), 10, 64)
if err != nil {
    writeBack(w, CodeHandleFail, "missing timestamp", http.StatusBadRequest)
    return
}

// block the repetition attack by correct the timestamp
sysTs := time.Now().UnixMilli()
if sysTs-reqTs > RequestLifespan.Milliseconds() {
    writeBack(w, CodeHandleFail, "request timeout", http.StatusBadRequest)
    return
}
```

### Miss Operation

*Miss Operation* is a protection when the user calls the non-idempotence interface multipart times. It happens when the network of the client is slow or other specific reason.

When a request came, we need to check whether the request has been handled by looking for the `OpsSignKey`. If it can be finded in redis, the request has been already handled.

```Golang
// main.go:351

// blockRepeatReq It avoids the repeat request.
// You can call it in any interface you want to avoid the misoperation.
func blockRepeatReq(sign string) bool {
	key := fmt.Sprintf("%v%v", OpsSignKey, sign)
	value, _ := rdb.Get(ctx, key).Result()

	return len(value) == 0
}
```

Pay attention to the lifespan of the `OpsSignKey`. The lifespan should be same with the `token` lifespan.

## Hint

01. There are a lot of protection to the interface. If you are interested to it, you can refer to other famous website.

02. It is important to **select the proper protection according to different business scenario**. Maybe we need to be scrict due the sensitive data. It is up to you.

## Reference

01. [API接口设计最佳实践](https://xie.infoq.cn/article/1490ba593f8271aeec0ca453f)

02. [浅谈如何保证API接口安全性](https://zhuanlan.zhihu.com/p/147788064)

## Tech Stack

01. Golang

02. Javascript

03. MySQL

04. Redis