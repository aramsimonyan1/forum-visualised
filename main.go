package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// Post structure
type Post struct {
	ID        string
	Title     string
	Content   string
	Category  string
	CreatedAt time.Time
}

// User structure
type User struct {
	ID       string
	Username string
	Password string
}

// Comment structure
type Comment struct {
	ID        string
	PostID    string
	Content   string
	CreatedAt time.Time
}

func main() {
	// Initialize the database
	initDB()

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Create routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/create-post", createPostHandler)
	http.HandleFunc("/post/", viewPostHandler)
	http.HandleFunc("/dislike/{postID}", dislikePostHandler)

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create posts table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			id TEXT PRIMARY KEY,
			title TEXT,
			content TEXT,
			category TEXT,
			created_at TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT,
			password TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Create comments table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS comments (
			id TEXT PRIMARY KEY,
			post_id TEXT,
			content TEXT,
			created_at TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve posts from the database
	posts, err := getPosts()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render the home page
	tmpl, err := template.New("home").Parse(`
		<html>
			<body>
				<h1>Forum</h1>
				{{range .}}
					<div>
						<h3><a href="/post/{{.ID}}">{{.Title}}</a></h3>
						<p>{{.Content}}</p>
						<p>Category: {{.Category}}</p>
						<p>Created at: {{.CreatedAt}}</p>
					</div>
				{{end}}
				<form action="/create-post" method="post">
					<label>Title:</label>
					<input type="text" name="title" required>
					<br>
					<label>Content:</label>
					<textarea name="content" required></textarea>
					<br>
					<label>Category:</label>
					<input type="text" name="category" required>
					<br>
					<button type="submit">Create Post</button>
				</form>
			</body>
		</html>
	`)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, posts)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is logged in (you may need to implement user authentication)
	// For simplicity, this example assumes the user is logged in.

	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Retrieve form data
	title := r.Form.Get("title")
	content := r.Form.Get("content")
	category := r.Form.Get("category")

	// Generate a unique ID for the post
	postID := uuid.New().String()

	// Insert the post into the database
	_, err = db.Exec(`
		INSERT INTO posts (id, title, content, category, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, postID, title, content, category, time.Now())
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve post ID from the URL
	vars := mux.Vars(r)
	postID := vars["id"]

	// Retrieve post details from the database
	post, err := getPostByID(postID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render the post page
	tmpl, err := template.New("post").Parse(`
		<html>
			<body>
				<h1>{{.Title}}</h1>
				<p>{{.Content}}</p>
				<p>Category: {{.Category}}</p>
				<p>Created at: {{.CreatedAt}}</p>
				<form action="/like/{{.ID}}" method="post">
					<button type="submit">Like</button>
				</form>
				<form action="/dislike/{{.ID}}" method="post">
					<button type="submit">Dislike</button>
				</form>
			</body>
		</html>
	`)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, post)
}

func likePostHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve post ID from the URL
	vars := mux.Vars(r)
	postID := vars["id"]

	// Implement the logic to increment the like count in the database
	// (you may need a separate table to store likes and dislikes)

	// Redirect back to the post page
	http.Redirect(w, r, fmt.Sprintf("/post/%s", postID), http.StatusSeeOther)
}

func dislikePostHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve post ID from the URL
	vars := mux.Vars(r)
	postID := vars["id"]

	// Implement the logic to increment the dislike count in the database
	// (you may need a separate table to store likes and dislikes)

	// Redirect back to the post page
	http.Redirect(w, r, fmt.Sprintf("/post/%s", postID), http.StatusSeeOther)
}

func getPosts() ([]Post, error) {
	rows, err := db.Query(`
		SELECT id, title, content, category, created_at
		FROM posts
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Category, &post.CreatedAt)
		if err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}

	return posts, nil
}

func getPostByID(postID string) (*Post, error) {
	var post Post
	err := db.QueryRow(`
		SELECT id, title, content, category, created_at
		FROM posts
		WHERE id = ?
	`, postID).Scan(&post.ID, &post.Title, &post.Content, &post.Category, &post.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &post, nil
}
