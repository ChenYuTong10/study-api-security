package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
)

var (
	ctx  context.Context
	rdb  *redis.Client
	conn *sql.DB
)

const (
	RequestLifespan = time.Minute * 1
	TokenLifespan   = time.Minute * 10
	OpsSignLifespan = time.Minute * 10

	CodeHandleFail    = -100
	CodeHandleSuccess = 0

	ApiTokenKey  = "api:token:"
	UserTokenKey = "usr:token:"
	OpsSignKey   = "ops:sign:"
)

type respInfo struct {
	Code    int64       `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details"`
}

type apiToken struct {
	AppId      string `json:"appId"`
	Secret     string `json:"secret"`
	CreateTime int64  `json:"createTime"`
}

type usrToken struct {
	Username   string `json:"username"`
	CreateTime int64  `json:"createTime"`
}

type dataInfo struct {
	Title   string `json:"title"`
	Desc    string `json:"desc"`
	Content string `json:"content"`
}

func init() {
	var err error

	if conn, err = sql.Open("mysql", os.Getenv("MYSQL_DEV_URL")); err != nil {
		log.Fatalln(err.Error())
	}

	conn.SetMaxOpenConns(3)

	ctx = context.Background()
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDRESS"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	if err = rdb.Ping(ctx).Err(); err != nil {
		log.Fatalln(err.Error())
	}
}

func getApiToken(w http.ResponseWriter, r *http.Request) {
	// check the request method
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()

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

	// check the blank or invalid of the payload
	appId := q.Get("appId")
	reqSign := q.Get("sign")

	if len(appId) == 0 || len(reqSign) == 0 {
		writeBack(w, CodeHandleFail, "missing app id or its sign", http.StatusBadRequest)
		return
	}

	// check the app id
	result := conn.QueryRow(`SELECT secret FROM t_app WHERE id = ?;`, appId)

	var secret string
	if err = result.Scan(&secret); err != nil && err != sql.ErrNoRows {
		log.Println(err.Error())
		http.Error(w, "db fail", http.StatusInternalServerError)
		return
	}

	if len(secret) == 0 {
		writeBack(w, CodeHandleFail, "nonexist app id", http.StatusBadRequest)
		return
	}

	str := fmt.Sprintf("appId%vsecret%vts%d", appId, secret, reqTs)
	serveSign := fmt.Sprintf("%x", md5.Sum([]byte(str)))

	if reqSign != serveSign {
		writeBack(w, CodeHandleFail, "sign not correct", http.StatusBadRequest)
		return
	}

	// generate token
	token, err := getUniqueId()
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "token generate fail", http.StatusInternalServerError)
		return
	}

	// store token to the redis
	tokenVals, err := json.Marshal(&apiToken{AppId: appId, Secret: secret, CreateTime: sysTs})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "json marshal fail", http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%v%v", ApiTokenKey, token)
	if err = rdb.Set(ctx, key, string(tokenVals), TokenLifespan).Err(); err != nil {
		log.Println(err.Error())
		http.Error(w, "cache fail", http.StatusInternalServerError)
		return
	}

	writeBack(w, CodeHandleSuccess, "success", token)
}

func getUserToken(w http.ResponseWriter, r *http.Request) {
	// check the request method
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check the request time
	reqTs, err := strconv.ParseInt(r.FormValue("ts"), 10, 64)
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

	// check the blank or invalid of the payload
	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) == 0 || len(password) == 0 {
		writeBack(w, CodeHandleFail, "missing username or password", http.StatusBadRequest)
		return
	}

	// check the username and password
	// commonly, check those by selecting database
	if username != "zhangsan" || password != "123456" {
		writeBack(w, CodeHandleFail, "username or password not correct", http.StatusBadRequest)
		return
	}

	// generate token
	token, err := getUniqueId()
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "token generate fail", http.StatusInternalServerError)
		return
	}

	// store token to the redis
	tokenVals, err := json.Marshal(&usrToken{Username: username, CreateTime: sysTs})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "json marshal fail", http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%v%v", UserTokenKey, token)
	if err = rdb.Set(ctx, key, string(tokenVals), TokenLifespan).Err(); err != nil {
		log.Println(err.Error())
		http.Error(w, "cache fail", http.StatusInternalServerError)
		return
	}

	writeBack(w, CodeHandleSuccess, "success", token)
}

func getPage(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	http.ServeFile(w, r, "index.html")
}

func getData(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

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

	// get the query payload
	size, sizeParseErr := strconv.ParseInt(q.Get("size"), 10, 0)
	page, pageParseErr := strconv.ParseInt(q.Get("pagenum"), 10, 0)
	if sizeParseErr != nil || pageParseErr != nil {
		writeBack(w, CodeHandleFail, "query payload not correct", "bad request")
		return
	}

	// check and range of the payload
	if size < 0 || size > 100 || page < 0 || page > 10 {
		writeBack(w, CodeHandleFail, "query payload out of range", "bad request")
		return
	}

	// query the data
	// commonly, the source of the data is database.
	var dataList []dataInfo
	var title, desc, content string

	start := (page - 1) * size
	end := page * size

	for i := start; i < end; i++ {
		title = fmt.Sprintf("title-%d", i)
		desc = fmt.Sprintf("desc-%d", i)
		content = fmt.Sprintf("content-%d", i)

		dataList = append(dataList, dataInfo{Title: title, Desc: desc, Content: content})
	}

	writeBack(w, CodeHandleSuccess, "success", dataList)
}

func createOrder(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check the request time
	reqTs, err := strconv.ParseInt(r.FormValue("ts"), 10, 64)
	if err != nil {
		writeBack(w, CodeHandleFail, "missing timestamp", "bad request")
		return
	}

	sysTs := time.Now().UnixMilli()
	if sysTs-reqTs > RequestLifespan.Milliseconds() {
		writeBack(w, CodeHandleFail, "request timeout", "bad request")
		return
	}

	// check the sign
	orderId := r.FormValue("orderId")
	username := r.FormValue("username")

	key := fmt.Sprintf("orderId%vts%vusername%v", orderId, reqTs, username)
	serveSign := fmt.Sprintf("%x", md5.Sum([]byte(key)))

	reqSign := r.URL.Query().Get("sign")
	if reqSign != serveSign {
		writeBack(w, CodeHandleFail, "sign not correct", "bad request")
		return
	}

	// avoid multipart call
	if !blockRepeatReq(serveSign) {
		// the interface has been called with multipart times
		writeBack(w, CodeHandleFail, "you have called many times", "bad request")
		return
	}

	// handle normal process

	// add the sign to the redis and remember ensure the atomicity of the handle normal process
	key = fmt.Sprintf("%v%v", OpsSignKey, serveSign)
	if err = rdb.Set(ctx, key, serveSign, OpsSignLifespan).Err(); err != nil {
		log.Println(err.Error())
		http.Error(w, "db fail", http.StatusInternalServerError)
		return
	}

	writeBack(w, CodeHandleSuccess, "success", make([]string, 0))
}

func writeBack(w http.ResponseWriter, code int64, message string, details interface{}) {
	w.Header().Set("Control-Access-Allow-Origin", "http://localhost:9090")

	resp, err := json.Marshal(&respInfo{Code: code, Message: message, Details: details})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "json marshal fail", http.StatusInternalServerError)
		return
	}

	w.Write(resp)
}

// blockRepeatReq It avoids the repeat request.
// You can call it in any interface you want to avoid the misoperation.
func blockRepeatReq(sign string) bool {
	key := fmt.Sprintf("%v%v", OpsSignKey, sign)
	value, _ := rdb.Get(ctx, key).Result()

	return len(value) == 0
}

// serve Controller of the non-authorization application.
// It will check the `authorization` field in every request header.
func apiServe(w http.ResponseWriter, r *http.Request) {

	// get the "Authorization" in the request header
	token := r.Header.Get("Authorization")

	// check the blank of the token
	if len(token) == 0 {
		writeBack(w, CodeHandleFail, "missing token", "bad request")
		return
	}

	// check api token
	key := fmt.Sprintf("%v%v", ApiTokenKey, token)
	value, _ := rdb.Get(ctx, key).Result()

	if len(value) == 0 {
		// the token is invalid
		writeBack(w, CodeHandleFail, "token is not correct", "bad request")
		return
	}

	switch r.URL.Path {
	case "/api/data":
		getData(w, r)
	default:
		http.Error(w, "404 not found", http.StatusNotFound)
	}
}

// usrServe Controller of the authorization application
func usrServe(w http.ResponseWriter, r *http.Request) {

	// get user token
	token := r.Header.Get("Authorization")

	// check the blank of the token
	if len(token) == 0 {
		writeBack(w, CodeHandleFail, "missing token", "bad request")
		return
	}

	// check api token
	key := fmt.Sprintf("%v%v", UserTokenKey, token)
	value, _ := rdb.Get(ctx, key).Result()

	if len(value) == 0 {
		// the token is invalid
		writeBack(w, CodeHandleFail, "no previlege", "bad request")
		return
	}

	switch r.URL.Path {
	case "/usr/order":
		createOrder(w, r)
	default:
		http.Error(w, "404 not found", http.StatusNotFound)
	}
}

func main() {
	http.HandleFunc("/api/", apiServe)
	http.HandleFunc("/usr/", usrServe)
	http.HandleFunc("/apitoken", getApiToken)
	http.HandleFunc("/usrtoken", getUserToken)
	http.HandleFunc("/", getPage)
	http.ListenAndServe(":9090", nil)
}
