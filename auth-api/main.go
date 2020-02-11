package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"auth-api/tool"
)

type User struct {
	// 大文字だと Public 扱い
	Id       int       `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Requests []Request `json:"Requests"`
}

type Request struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Url     string `json:"url"`
	Comment string `json:"comment"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

// JSON 形式で結果を返却
// data interface{} とすると、どのような変数の型でも引数として受け取ることができる
func responseByJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
	return
}

// レスポンスにエラーを突っ込んで、返却するメソッド
func errorInResponse(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status) // 400 とか 500 などの HTTP status コードが入る
	json.NewEncoder(w).Encode(error)
	return
}

// Token 作成関数
func createToken(user User) (string, error) {
	var err error

	// 鍵となる文字列(多分なんでもいい)
	secret := "secret"

	// Token を作成
	// jwt -> JSON Web Token - JSON をセキュアにやり取りするための仕様
	// jwtの構造 -> {Base64 encoded Header}.{Base64 encoded Payload}.{Signature}
	// HS254 -> 証明生成用(https://ja.wikipedia.org/wiki/JSON_Web_Token)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "adatamonkey", // JWT の発行者が入る(文字列(__init__)は任意)
	})

	//Dumpを吐く
	spew.Dump(token)

	tokenString, err := token.SignedString([]byte(secret))

	fmt.Println("-----------------------------")
	fmt.Println("tokenString:", tokenString)

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	var jwt JWT

	// r.body に何が帰ってくるか確認
	fmt.Println(r.Body)

	// https://golang.org/pkg/encoding/json/#NewDecoder
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email は必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	// パスワードのハッシュを生成
	// https://godoc.org/golang.org/x/crypto/bcrypt#GenerateFromPassword
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("パスワード: ", user.Password)
	fmt.Println("ハッシュ化されたパスワード", hash)

	user.Password = string(hash)
	fmt.Println("コンバート後のパスワード: ", user.Password)

	sql_query := "INSERT INTO USERS(EMAIL, PASSWORD) VALUES($1, $2) RETURNING ID;"

	// query 発行
	// Scan で、Query 結果を変数に格納
	err = db.QueryRow(sql_query, user.Email, user.Password).Scan(&user.Id)

	if err != nil {
		error.Message = "サーバーエラー"
		errorInResponse(w, http.StatusInternalServerError, error)
		return
	}

	// // DB に登録できたらパスワードをからにしておく
	// user.Password = ""
	// w.Header().Set("Content-Type", "application/json")

	token, err := createToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseByJSON(w, jwt)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	var jwt JWT

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email は必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは、必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
	}

	password := user.Password
	fmt.Println("password: ", password)

	// 認証キー(Emal)のユーザー情報をDBから取得
	row := db.QueryRow("SELECT * FROM USERS WHERE email=$1;", user.Email)
	// ハッシュ化している
	err := row.Scan(&user.Id, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows { // https://golang.org/pkg/database/sql/#pkg-variables
			error.Message = "ユーザが存在しません。"
			errorInResponse(w, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	hasedPassword := user.Password
	fmt.Println("hasedPassword: ", hasedPassword)

	err = bcrypt.CompareHashAndPassword([]byte(hasedPassword), []byte(password))

	if err != nil {
		error.Message = "無効なパスワードです。"
		errorInResponse(w, http.StatusUnauthorized, error)
		return
	}

	token, err := createToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseByJSON(w, jwt)
}

func request(w http.ResponseWriter, r *http.Request) {
	var request Request
	var error Error

	json.NewDecoder(r.Body).Decode(&request)

	if request.Email == "" {
		error.Message = "Email は必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if request.Name == "" {
		error.Message = "リクエストは必須です。"
		errorInResponse(w, http.StatusBadRequest, error)
	}

	// 認証キー(Emal)のユーザー情報をDBから取得
	user_id := db.QueryRow("SELECT id FROM USERS WHERE email=$1;", request.Email)
	// ハッシュ化している
	var id int
	err := user_id.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows { // https://golang.org/pkg/database/sql/#pkg-variables
			error.Message = "ユーザが存在しません。"
			errorInResponse(w, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	fmt.Println(request.Name, request.Url, request.Comment, id)

	// 認証キー(Emal)のユーザー情報をDBから取得
	ins, err := db.Prepare("INSERT INTO REQUESTS(NAME, URL, COMMENT, USER_ID) VALUES($1, $2, $3, $4);")

	if err != nil {
		log.Fatal(err)
	}
	ins.Exec(request.Name, request.Url, request.Comment, id)

	defer ins.Close()

}

func verifyEndpoint(w http.ResponseWriter, r *http.Request) {
	var errorObject Error

	// HTTP リクエストヘッダーを読み取る
	authHeader := r.Header.Get("Authorization")

	// Restlet Client から以下のような文字列を渡す
	// bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3Q5OUBleGFtcGxlLmNvLmpwIiwiaXNzIjoiY291cnNlIn0.7lJKe5SlUbdo2uKO_iLzzeGoxghG7SXsC3w-4qBRLvs
	bearerToken := strings.Split(authHeader, " ")
	fmt.Println("bearerToken: ", bearerToken)

	authToken := bearerToken[0]

	token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("エラーが発生しました。")
		}
		return []byte("secret"), nil
	})

	if error != nil {
		errorObject.Message = error.Error()
		errorInResponse(w, http.StatusUnauthorized, errorObject)
		return
	}

	if token.Valid {
		// レスポンスを返す
		claims, _ := token.Claims.(jwt.MapClaims)
		email, _ := claims["email"].(string)

		var user User
		var error Error

		// 認証キー(Emal)のユーザー情報をDBから取得
		row := db.QueryRow("SELECT * FROM USERS WHERE email=$1;", email)
		// ハッシュ化している
		err := row.Scan(&user.Id, &user.Email, &user.Password)
		if err != nil {
			if err == sql.ErrNoRows { // https://golang.org/pkg/database/sql/#pkg-variables
				error.Message = "ユーザが存在しません。"
				errorInResponse(w, http.StatusBadRequest, error)
			} else {
				log.Fatal(err)
			}
		}

		fmt.Println(user.Id)

		GetRequest(user.Id)

	} else {
		errorObject.Message = error.Error()
		errorInResponse(w, http.StatusUnauthorized, errorObject)
		return
	}
}

func GetRequest(id int) {

	rows, err := db.Query("SELECT requests.id, requests.name, requests.url, requests.comment, user_id, users.email FROM requests INNER JOIN users ON requests.user_id = users.id WHERE user_id = $1", id)
	if err != nil {
		log.Fatal(err)
	}

	var user = User{}

	for rows.Next() {
		var id int
		var name string
		var user_id int
		var email string
		var url string
		var comment string
		if err := rows.Scan(&id, &name, &user_id, &email, &url, &comment); err != nil {
			log.Fatal(err)
		}

		user.Id = user_id

		user.Email = email

		request := Request{Name: name, Url: url, Comment: comment}
		user.Requests = append(user.Requests, request)

	}

	fmt.Println(user)

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	jsonBytes, err := json.Marshal(user)
	if err != nil {
		fmt.Println("JSON Marshal error:", err)
		return
	}
	fmt.Println(string(jsonBytes))

	rows.Close()

	return
}

// verifyEndpoint のラッパーみたいなもの
func tokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var errorObject Error

		// HTTP リクエストヘッダーを読み取る
		authHeader := r.Header.Get("Authorization")

		// Restlet Client から以下のような文字列を渡す
		// bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3Q5OUBleGFtcGxlLmNvLmpwIiwiaXNzIjoiY291cnNlIn0.7lJKe5SlUbdo2uKO_iLzzeGoxghG7SXsC3w-4qBRLvs
		bearerToken := strings.Split(authHeader, " ")
		fmt.Println("bearerToken: ", bearerToken)

		if len(bearerToken) == 1 {
			authToken := bearerToken[0]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("エラーが発生しました。")
				}
				return []byte("secret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				errorInResponse(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				// レスポンスを返す
				claims, _ := token.Claims.(jwt.MapClaims)
				id, _ := claims["email"].(string)

				fmt.Println(id)

				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				errorInResponse(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Token が無効です。"

			fmt.Println(errorObject.Message)

			return
		}
	})
}

// dbインスタンス格納用
var db *sql.DB

func main() {
	// parmas.go から DB の URL を取得
	i := tool.Info{}

	// Convert
	// https://github.com/lib/pq/blob/master/url.go
	// "postgres://bob:secret@1.2.3.4:5432/mydb?sslmode=verify-full"
	// ->　"user=bob password=secret host=1.2.3.4 port=5432 dbname=mydb sslmode=verify-full"
	pgUrl, err := pq.ParseURL(i.GetDBUrl())

	// 戻り値に err を返してくるので、チェック
	if err != nil {
		// エラーの場合、処理を停止する
		log.Fatal()
	}

	// DB 接続
	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}

	// DB 疎通確認
	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	// urls.py
	router := mux.NewRouter()

	// endpoint
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/request", request).Methods("POST")
	// service はあとで記述する
	router.HandleFunc("/verify", tokenVerifyMiddleWare(verifyEndpoint)).Methods("GET")

	// console に出力する
	log.Println("サーバー起動 : 8000 port で受信")

	// log.Fatal は、異常を検知すると処理の実行を止めてくれる
	log.Fatal(http.ListenAndServe(":8000", router))
}
