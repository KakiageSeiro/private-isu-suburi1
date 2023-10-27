package main

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"

	"net/http/pprof"
)

var (
	db    *sqlx.DB
	memcacheClient *memcache.Client
	store *gsm.MemcacheStore
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient = memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(string(out), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, post := range results {
		// コメント件数を取得■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
		// memcachedにあるならそれをつかう。なければDBから取得する
		memcachedKeyAllcomments := "comments." + strconv.Itoa(post.ID) + ".count"
		itemOfAllcomments, err := memcacheClient.Get(memcachedKeyAllcomments);
		if err != nil {
			// キャッシュになかったのでDBから取得する
			err := db.Get(&post.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", post.ID)
			if err != nil {
				return nil, err
			}

			// DBから取得した結果をキャッシュする
			err = memcacheClient.Set(&memcache.Item{Key: memcachedKeyAllcomments, Value: []byte(strconv.Itoa(post.CommentCount)), Expiration: 10})
			if err != nil {
				return nil, err
			}
		} else {
			// キャッシュあった
			post.CommentCount, err = strconv.Atoi(string(itemOfAllcomments.Value))
			if err != nil {
				return nil, err
			}
		}

		// コメントそのものと、コメントしたユーザーを合わせて取得■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
		memcachedKeyComments := "comments." + strconv.Itoa(post.ID)
		var comments []Comment
		itemOfComments, err := memcacheClient.Get(memcachedKeyComments)
		if err == nil {
			// キャッシュある場合。コメントは複数なので、jsonとして保存、取出する。
			err := json.Unmarshal(itemOfComments.Value, &comments)
			if err != nil {
				return nil, err
			}
		} else {
			// キャッシュがない場合はDBから取得する

			var commentDtoList []struct {
				C_ID     int `db:"c_id"`
				C_PostID  int    `db:"post_id"`
				C_UserID    int       `db:"user_id"`
				C_Comment   string    `db:"comment"`
				C_CreatedAt time.Time `db:"c_created_at"`

				U_ID          int    `db:"u_id"`
				U_AccountName string `db:"account_name"`
				U_Passhash  string `db:"passhash"`
				U_Authority int       `db:"authority"`
				U_DelFlg    int       `db:"del_flg"`
				U_CreatedAt time.Time `db:"u_created_at"`
			}

			query :=
				"SELECT " +
					"c.`id` AS c_id , " +
					"c.`post_id`, " +
					"c.`user_id`, " +
					"c.`comment`, " +
					"c.`created_at` AS c_created_at, " +

					"u.`id` AS u_id, " +
					"u.`account_name`, " +
					"u.`passhash`, " +
					"u.`authority`, " +
					"u.`del_flg`, " +
					"u.`created_at` AS u_created_at " +
				"FROM `comments` AS c " +
				"JOIN `users` AS u " +
					"ON c.`user_id` = u.`id` " +
				"WHERE c.`post_id` = ? ORDER BY c.`created_at` DESC"
			if !allComments {
				query += " LIMIT 3"
			}
			err = db.Select(&commentDtoList, query, post.ID)
			if err != nil {
				return nil, err
			}

			// 結果をComment構造体にマッピング
			for _, dto := range commentDtoList {
				comment := Comment{
					ID:        dto.C_ID,
					PostID:    dto.C_PostID,
					UserID:    dto.C_UserID,
					Comment:   dto.C_Comment,
					CreatedAt: dto.C_CreatedAt,
				}

				comment.User = User{
					ID:          dto.U_ID,
					AccountName: dto.U_AccountName,
					Passhash:    dto.U_Passhash,
					Authority:   dto.U_Authority,
					DelFlg:      dto.U_DelFlg,
					CreatedAt:   dto.U_CreatedAt,
				}

				comments = append(comments, comment)
			}

			// DBから取得した結果をキャッシュする
			commentsJSON, err := json.Marshal(comments)
			if err != nil {
				return nil, err
			}
			err = memcacheClient.Set(&memcache.Item{Key: memcachedKeyComments, Value: commentsJSON, Expiration: 10})
			if err != nil {
				return nil, err
			}
		}

		// コメントを逆順にする
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		post.Comments = comments

		post.CSRFToken = csrfToken

		posts = append(posts, post)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}


func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)


	var result_dto_list []struct {
		ID           int    `db:"id"`
		UserID       int    `db:"user_id"`
		Body         string `db:"body"`
		Mime         string `db:"mime"`
		AccountName  string `db:"account_name"`
	}

	results := []Post{}

	sql :=
		"SELECT posts.id, posts.user_id, posts.body, posts.mime, users.account_name " +
		"FROM `posts` " +
		"JOIN `users` " +
			"ON (posts.user_id = users.id) " +
		"WHERE users.del_flg = 0 " +
		"ORDER BY posts.created_at DESC " +
		"LIMIT 20"
	err := db.Select(&result_dto_list, sql)
	if err != nil {
		log.Print(err)
		return
	}


	// 結果をPost構造体にマッピング
	for _, result_dto := range result_dto_list {
		post := Post{
			ID:           result_dto.ID,
			UserID:       result_dto.UserID,
			Body:         result_dto.Body,
			Mime:         result_dto.Mime,
		}
		// ここでUserフィールドを埋める
		post.User = User{
			AccountName: result_dto.AccountName,
		}

		// resultsにPostを追加
		results = append(results, post)
	}





	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}


	var result_dto_list []struct {
		ID           int    `db:"id"`
		UserID       int    `db:"user_id"`
		Body         string `db:"body"`
		Mime         string `db:"mime"`
		AccountName  string `db:"account_name"`
	}

	results := []Post{}
	sql :=
		"SELECT posts.id, posts.user_id, posts.body, posts.mime, users.account_name " +
			"FROM `posts` " +
			"JOIN `users` " +
			"ON (posts.user_id = users.id) " +
			"WHERE users.del_flg = 0 " +
			"AND posts.user_id = ? " +
			"ORDER BY posts.created_at DESC " +
			"LIMIT 20"
	err = db.Select(&result_dto_list, sql, user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	// 結果をPost構造体にマッピング
	for _, result_dto := range result_dto_list {
		post := Post{
			ID:           result_dto.ID,
			UserID:       result_dto.UserID,
			Body:         result_dto.Body,
			Mime:         result_dto.Mime,
		}
		// ここでUserフィールドを埋める
		post.User = User{
			AccountName: result_dto.AccountName,
		}

		// resultsにPostを追加
		results = append(results, post)
	}



	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	var result_dto_list []struct {
		ID           int    `db:"id"`
		UserID       int    `db:"user_id"`
		Body         string `db:"body"`
		Mime         string `db:"mime"`
		AccountName  string `db:"account_name"`
	}

	sql :=
		"SELECT posts.id, posts.user_id, posts.body, posts.mime, users.account_name " +
			"FROM `posts` " +
			"JOIN `users` " +
			"ON (posts.user_id = users.id) " +
			"WHERE users.del_flg = 0 " +
			"AND posts.created_at <= ? " +
			"ORDER BY posts.created_at DESC " +
			"LIMIT 20"
	err = db.Select(&result_dto_list, sql, t.Format(ISO8601Format))
	if err != nil {
		log.Print(err)
		return
	}


	// 結果をPost構造体にマッピング
	for _, result_dto := range result_dto_list {
		post := Post{
			ID:           result_dto.ID,
			UserID:       result_dto.UserID,
			Body:         result_dto.Body,
			Mime:         result_dto.Mime,
		}
		// ここでUserフィールドを埋める
		post.User = User{
			AccountName: result_dto.AccountName,
		}

		// resultsにPostを追加
		results = append(results, post)
	}




	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	var result_dto_list []struct {
		ID           int    `db:"id"`
		UserID       int    `db:"user_id"`
		Body         string `db:"body"`
		Mime         string `db:"mime"`
		AccountName  string `db:"account_name"`
	}

	sql :=
		"SELECT posts.id, posts.user_id, posts.body, posts.mime, users.account_name " +
			"FROM `posts` " +
			"JOIN `users` " +
			"ON (posts.user_id = users.id) " +
			"WHERE users.del_flg = 0 " +
			"AND posts.id = ? " +
			"ORDER BY posts.created_at DESC " +
			"LIMIT 20"
	err = db.Select(&result_dto_list, sql, pid)
	if err != nil {
		log.Print(err)
		return
	}


	// 結果をPost構造体にマッピング
	for _, result_dto := range result_dto_list {
		post := Post{
			ID:           result_dto.ID,
			UserID:       result_dto.UserID,
			Body:         result_dto.Body,
			Mime:         result_dto.Mime,
		}
		// ここでUserフィールドを埋める
		post.User = User{
			AccountName: result_dto.AccountName,
		}

		// resultsにPostを追加
		results = append(results, post)
	}




	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

// ツイートする処理。Post(投稿/マイクロブログ)をPost(HTTPメソッド)するという表現になるのでわかりにくいけどツイートをPostと言えばわかりやすい
func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// 画像があるかどうかチェック
	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// ファイルタイプと拡張子を決定する
	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// ファイル読み込み
	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	// ファイルサイズチェック
	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// RDBにinsert
	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		"", // バイナリはDBに保存せず静的ファイルにすることにした
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	// 採番されたidを取得
	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// アップロードされたテンポラリファイルを静的ファイルにする
	filepath := path.Join("/home/isucon/private_isu/webapp/public/image", strconv.FormatInt(pid, 10)+"."+ext)
	err = os.WriteFile(filepath, filedata, 0644) // ファイルを作成する
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := chi.URLParam(r, "ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)

		// もともとRDBにバイナリとして保存していた画像は静的ファイルにするようにしたので、取得したときに静的ファイル化することで次回取得時はnginxが静的ファイル置き場のディレクトリから配信してくれるようになる
		// というわけでpost.Imgdataを静的ファイルにする
		filepath := path.Join("/home/isucon/private_isu/webapp/public/image", strconv.Itoa(post.ID)+"."+ext)
		err = os.WriteFile(filepath, post.Imgdata, 0644) // ファイルを作成する
		if err != nil {
			return
		}

		_, err = w.Write(post.Imgdata)
		if err != nil {
			return
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

// アカウントのBan処理
func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	// del_flg=1でBanを表現してる。0は通常のユーザー
	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	r.HandleFunc("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)

	server := &http.Server{
		Addr:         ":8080", 				// サーバーのポート
		Handler:      r,       				// ルーターを設定
		ReadTimeout:  110 * time.Second, 	// リクエストの読み取りタイムアウト
		WriteTimeout: 110 * time.Second, 	// レスポンスの書き込みタイムアウト
	}
	log.Fatal(server.ListenAndServe())
}

