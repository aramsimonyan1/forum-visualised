package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID       string
	Username string
	Password string
}

type Post struct {
	ID            string
	Username      string
	Title         string
	Content       string
	Categories    []string
	CreatedAt     time.Time
	LikesCount    int
	DislikesCount int
	Comments      []Comment
	IsLoggedIn    bool
}

type PostInteraction struct {
	UserID string
	PostID string
	Action string
}

type Comment struct {
	ID            string
	PostID        string
	Username      string
	Content       string
	CreatedAt     time.Time
	LikesCount    int
	DislikesCount int
}

type CommentInteraction struct {
	UserID    string
	CommentID string
	Action    string
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			username TEXT,
			password TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			user_email TEXT,
			FOREIGN KEY (user_email) REFERENCES users(email)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			title TEXT,
			content TEXT,
			categories TEXT,
			created_at TIMESTAMP,
			likes_count INT DEFAULT 0,
            dislikes_count INT DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS post_interactions (
			user_id TEXT,
			post_id TEXT,
			action TEXT,
			PRIMARY KEY (user_id, post_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (post_id) REFERENCES posts(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS comments (
			id TEXT PRIMARY KEY,
			post_id TEXT,
			user_id TEXT,
			content TEXT,
			created_at TIMESTAMP,
			likes_count INT DEFAULT 0,
            dislikes_count INT DEFAULT 0,
            FOREIGN KEY (post_id) REFERENCES posts(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS comment_interactions (
        user_id TEXT,
        comment_id TEXT,
        action TEXT,
        PRIMARY KEY (user_id, comment_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (comment_id) REFERENCES comments(id)
    )
`)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Initialize the database
	initDB()

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public Routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/create-post", createPostHandler)
	http.HandleFunc("/like/{postID}", likePostHandler)
	http.HandleFunc("/dislike/{postID}", dislikePostHandler)
	http.HandleFunc("/add-comment/{postID}", addCommentHandler)
	http.HandleFunc("/like-comment/{postID}", likeCommentHandler)
	http.HandleFunc("/dislike-comment/{postID}", dislikeCommentHandler)
	http.HandleFunc("/filter", categoryFilterHandler)
	http.HandleFunc("/posts-chart", userPostsChartHandler)
	http.HandleFunc("/comments-chart", commentsOnUserPostsChartHandler)

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Function retrieves the userID from the given HTTP request
func getUserID(r *http.Request) string { // Takes an http.Request object (r) as its parameter. This object represents an incoming HTTP request.
	cookie, err := r.Cookie("forum-session") // Attempt to retrieve the "forum-session" cookie from the request
	if err != nil || cookie.Value == "" {    // if there is an error retrieving the cookie (e.g. the cookie is not present or there is some issue accessing it.)
		log.Println("No valid session cookie found. User is not logged in.")
		return "" // Return an empty string (this indicates that the user ID could not be retrieved from the cookie)
	}
	// Retrieve the user ID associated with the session from the database
	var userID string
	err = db.QueryRow(`
        SELECT id
        FROM users
        WHERE email = (
            SELECT user_email
            FROM sessions
            WHERE session_id = ?
        )
    `, cookie.Value).Scan(&userID)

	if err != nil {
		// Handle the case where no row is found (user not logged in)
		if err == sql.ErrNoRows {
			return "" // Return an empty string to indicate authentication failure
		}
		log.Println(err) // Log other errors
		return ""        // Return an empty string in case of other errors as well
	}

	return userID
}

// Invalidate existing sessions for a user
func invalidateSessionsForUser(email string) error {
	_, err := db.Exec(`
		DELETE FROM sessions
		WHERE user_email = ?
	`, email)
	return err
}

// Variable represents the minimum required password entropy, which is a measure of password strength based on unpredictability.
const minEntropyBits = 60

// Function ensures that new users can securely create accounts in the forum application.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Register handler received a request")
	// Only HTTP POST requests are processed. Return HTTP 405 otherwise.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data. Return HTTP 400 response if it fails.
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fmt.Println("Form values:", r.Form)

	// Retrieve form data
	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")

	fmt.Printf("Received data - Email: %s, Username: %s, Password: %s\n", email, username, password)

	// Check if email is empty
	if email == "" {
		http.Error(w, "Email cannot be empty", http.StatusBadRequest)
		return
	}

	// Check if email is already taken
	if emailExists(email) {
		errorMessage := "This email is already registered in database. Use your password to login."
		// Display an error message and redirect after 5 seconds.  //%s is a placeholder replaced by the value of errorMessage variable
		errorPage := fmt.Sprintf(`
            <html>
				<body style="font-size: 25px;">
                    <p>%s</p>                                        
                    <meta http-equiv="refresh" content="5;url=/">
                </body>
            </html>
        `, errorMessage)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(errorPage))
		return
	}

	// The entered password is validated using a password strength checker
	err = passwordvalidator.Validate(password, minEntropyBits)
	if err != nil {
		http.Error(w, "Weak password: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Function takes password coverted into a byte slice and the cost factor, to securely hash a password using the bcrypt algorithm to be stored in the database.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) // bcrypt.DefaultCost is a constant provided by the bcrypt package, representing
	if err != nil {                                                                          // the default cost factor that determines how computationally expensive the hash function is.
		log.Println(err) // If there was an error, during the hashing process it logs the error using log.Println(err) and
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return // returns an HTTP 500 Internal Server Error response using http.Error.
	}

	// Generate a unique user ID and insert the user details into the database
	userID := uuid.New().String()
	_, err = db.Exec(`
        INSERT INTO users (id, email, username, password)
        VALUES (?, ?, ?, ?)
    `, userID, email, username, string(hashedPassword))
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If all steps succeeded print in the terminal,
	fmt.Println("Successfully registered a new user")

	// as well as in web browser URL address bar, and redirect to the home page to log in.
	http.Redirect(w, r, "/home?message=Registration%20successful", http.StatusSeeOther)
}

// Makes database query to count occurrences of the given email in the users table. If the email exists, the function returns an error message.
func emailExists(email string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		log.Println(err)
		return true
	}
	return count > 0
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Only HTTP POST requests are processed. Return HTTP 405 otherwise.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data. Return HTTP 400 response if it fails.
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Retrieve form data
	email := r.Form.Get("email")
	password := r.Form.Get("password")

	// Query users table for the corresponding email
	var userID, hashedPassword string
	err = db.QueryRow(`
		SELECT id, password
		FROM users
		WHERE email = ?
	`, email).Scan(&userID, &hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			errorMessage := "Incorrect email. Redirecting to the main page..."
			// Display an error message and redirect after 4 seconds
			errorPage := fmt.Sprintf(`
				<html>
					<body style="font-size: 2em;">
						<p>%s</p>
						<meta http-equiv="refresh" content="4;url=/">
					</body>
				</html>
			`, errorMessage)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(errorPage))
		} else {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Invalidate existing sessions (if any) for the user
	err = invalidateSessionsForUser(email)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		errorMessage := "Invalid password. Please try again."
		// Display an error message and redirect after 4 seconds
		errorPage := fmt.Sprintf(`
            <html>
				<body>
					<p style="font-size: 2em;">%s</p>
                    <meta http-equiv="refresh" content="4;url=/">
                </body>
            </html>
        `, errorMessage)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(errorPage))
		return
	}

	// Generate a unique session ID and print in the terminal
	sessionID := uuid.New().String()
	log.Printf("User %s logged in. New session ID: %s\n", email, sessionID)

	// Store the session ID and user's email in the sessions table for consistent identification
	_, err = db.Exec(`
        INSERT INTO sessions (session_id, user_email)
        VALUES (?, ?)
    `, sessionID, email)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store the session ID in a cookie named forum-session with an expiration time of 24 hours.
	http.SetCookie(w, &http.Cookie{
		Name:    "forum-session",
		Value:   sessionID,
		Expires: time.Now().Add(2 * time.Hour),
		Path:    "/",
	})

	// Redirect to the home page after successful login
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie from the request
	sessionCookie, err := r.Cookie("forum-session")
	if err != nil {
		log.Println("Session cookie not found or already expired:", err)
	} else {
		sessionID := sessionCookie.Value
		log.Printf("Logging out user with session ID: %s\n", sessionID)

		// Remove the session record from the database
		_, err = db.Exec(`DELETE FROM sessions WHERE session_id = ?`, sessionID)
		if err != nil {
			log.Printf("Failed to delete session from database: %v", err)
		}
	}

	// // Invalidate the session cookie by setting an expired timestamp
	http.SetCookie(w, &http.Cookie{
		Name:    "forum-session",
		Value:   "",                             // Empty value to clear the session ID
		Expires: time.Now().Add(-1 * time.Hour), // Set expiration to the past to force removal
		Path:    "/",                            // Ensure it applies to the entire site
	})

	// Redirect the user to the homepage after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the user is logged in
	userID := getUserID(r)
	isLoggedIn := userID != "" // User is logged in if getUserID returns a valid ID

	if isLoggedIn {
		log.Printf("User is logged in. UserID: %s", userID)
	}

	// Check if the request contains category filter parameters
	categoryFilter := r.FormValue("category")

	// Retrieve posts and comments for display based on category filter
	var posts []Post
	var err error

	switch filter := r.FormValue("filter"); filter {
	case "user":
		// Retrieve posts created by the user
		posts, err = getPostsByUser(getUserID(r))
	case "liked":
		// Retrieve posts liked by the user
		posts, err = getLikedPosts(getUserID(r))
	default:
		// Retrieve selected category posts
		posts, err = getPostsFromDatabase(categoryFilter)
	}

	if err != nil {
		log.Printf("Error getting posts from the database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Retrieve comments for each post
	for i := range posts {
		comments, err := getCommentsForPost(posts[i].ID)
		if err != nil {
			log.Printf("Error getting comments for post %s: %v", posts[i].ID, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		posts[i].Comments = comments
	}

	// Display posts and comments to the user
	tmpl, err := template.ParseFiles("templates/home.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Pass additional data to the template, such as selected category for display
	tmplData := struct {
		IsLoggedIn       bool
		Posts            []Post
		SelectedCategory string
	}{
		IsLoggedIn:       isLoggedIn,
		Posts:            posts,
		SelectedCategory: categoryFilter,
	}

	if err := tmpl.Execute(w, tmplData); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Function takes the category value from the form submission and appends it as a query parameter to the home page URL (/?category=<selected_category>).
func categoryFilterHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/?category="+r.FormValue("category"), http.StatusSeeOther)
}

// Function fetches posts from the database, applying a category filter if specified.
func getPostsFromDatabase(categoryFilter string) ([]Post, error) {
	var posts []Post
	var query string
	var args []interface{}

	// If categoryFilter is not empty, split the categoryFilter into individual categories.
	if categoryFilter != "" {
		categories := strings.Split(categoryFilter, ",")

		// Build the query dynamically based on the number of categories
		query = `
            SELECT posts.id, posts.title, posts.content, posts.categories, posts.created_at, 
                   posts.likes_count, posts.dislikes_count, users.username
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE `
		for i, category := range categories {
			if i > 0 {
				query += " OR "
			}
			query += "INSTR(posts.categories, ?) > 0" // Function checks whether a substring (category) is present in the categories column.
			args = append(args, category)             // Each category is added as a query parameter using args, which is passed to db.Query() to prevent SQL injection.
		}
		query += `
            ORDER BY posts.created_at DESC
        `
		// If no category is provided (indicated by an empty string), the query retrieves all posts without any filtering, ordered by the created_at timestamp in descending order (latest posts first).
	} else {
		query = `
            SELECT posts.id, posts.title, posts.content, posts.categories, posts.created_at, 
                   posts.likes_count, posts.dislikes_count, users.username
            FROM posts
            JOIN users ON posts.user_id = users.id
            ORDER BY posts.created_at DESC
        `
	}

	// Execute the SQL query, passing any category filter values as arguments
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // ensures that the database connection is properly closed after query processing.

	// Each row is scanned and mapped to the Post struct fields.
	for rows.Next() {
		var post Post
		var categoriesString string
		err := rows.Scan(&post.ID, &post.Title, &post.Content, &categoriesString, &post.CreatedAt, &post.LikesCount, &post.DislikesCount, &post.Username)
		if err != nil {
			return nil, err
		}

		// categoriesString is split using strings.Split() to convert the comma-separated string of categories into a slice ([]string).
		post.Categories = strings.Split(categoriesString, ",")

		// Comments for each post are retrieved using getCommentsForPost(post.ID) and appended to the Comments field.
		comments, err := getCommentsForPost(post.ID)
		if err != nil {
			return nil, err
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	return posts, nil // A slice of (filtered/all posts) Post objects is returned along with a nil error if no issues occur.
}

// getCommentsForPost retrieves all comments for a specific post from the database
func getCommentsForPost(postID string) ([]Comment, error) {
	rows, err := db.Query(`
		SELECT comments.id, comments.post_id, users.username, comments.content, comments.created_at, comments.likes_count, comments.dislikes_count
		FROM comments
		JOIN users ON comments.user_id = users.id
		WHERE comments.post_id = ?
		ORDER BY created_at DESC
	`, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var c Comment
		err := rows.Scan(&c.ID, &c.PostID, &c.Username, &c.Content, &c.CreatedAt, &c.LikesCount, &c.DislikesCount)
		if err != nil {
			return nil, err
		}

		comments = append(comments, c)
	}
	return comments, nil
}

// getPostsByUser retrieves posts created by a specific user from the database
func getPostsByUser(userID string) ([]Post, error) {
	var posts []Post

	rows, err := db.Query(`
		SELECT posts.id, posts.title, posts.content, posts.categories, posts.created_at, posts.likes_count, posts.dislikes_count, users.username
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE posts.user_id = ?
		ORDER BY posts.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // ensures that the database connection is properly closed after query processing.

	// Each row is scanned and mapped to the Post struct fields.
	for rows.Next() {
		var post Post
		var categoriesString string
		err := rows.Scan(&post.ID, &post.Title, &post.Content, &categoriesString, &post.CreatedAt, &post.LikesCount, &post.DislikesCount, &post.Username)
		if err != nil {
			return nil, err
		}

		// categoriesString is split using strings.Split() to convert the comma-separated string of categories into a slice ([]string).
		post.Categories = strings.Split(categoriesString, ",")

		// Comments for each post are retrieved using getCommentsForPost(post.ID) and appended to the Comments field.
		comments, err := getCommentsForPost(post.ID)
		if err != nil {
			return nil, err
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	return posts, nil // A slice of Post objects is returned along with a nil error if no issues occur.
}

// Function retrieves posts that a user has liked by querying the post_interactions table
func getLikedPosts(userID string) ([]Post, error) {
	var posts []Post

	// INNER JOIN query between posts, users, and post_interactions to ensure that only posts liked by the specified user are returned
	rows, err := db.Query(`
		SELECT p.id, p.title, p.content, p.categories, p.created_at, p.likes_count, p.dislikes_count, u.username
		FROM posts p
		JOIN users u ON p.user_id = u.id
		INNER JOIN post_interactions pi ON p.id = pi.post_id
		WHERE pi.user_id = ? AND pi.action = 'like'
		ORDER BY p.created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // ensures that the database connection is properly closed after query processing.

	for rows.Next() {
		var post Post
		var categoriesString string
		err := rows.Scan(&post.ID, &post.Title, &post.Content, &categoriesString, &post.CreatedAt, &post.LikesCount, &post.DislikesCount, &post.Username)
		if err != nil {
			return nil, err
		}

		// categoriesString is split using strings.Split() to convert the comma-separated string of categories into a slice ([]string).
		post.Categories = strings.Split(categoriesString, ",")

		// Comments for each post are retrieved using getCommentsForPost(post.ID) and appended to the Comments field.
		comments, err := getCommentsForPost(post.ID)
		if err != nil {
			return nil, err
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	return posts, nil // A slice of Post objects is returned along with a nil error if no issues occur.
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	// getUserID(r) extracts the session ID from the cookie and queries the database to retrieve the user ID.
	userID := getUserID(r)

	// If getUserID(r) returns an empty string, the user is redirected because they are not authenticated.
	if userID == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// User is logged in, and no error, parse the form data (proceed with post creation)
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Retrieve form data
	title := r.Form.Get("title")
	content := r.Form.Get("content")
	categories := r.Form["categories[]"]

	// Generate a unique ID for the post
	postID := uuid.New().String()

	// Insert the post into the database
	_, err = db.Exec(`
		INSERT INTO posts (id, user_id, title, content, categories, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, postID, getUserID(r), title, content, strings.Join(categories, ","), time.Now())
	if err != nil {
		log.Printf("Error inserting post into the database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func addCommentHandler(w http.ResponseWriter, r *http.Request) {
	// getUserID(r) extracts the session ID from the cookie and queries the database to retrieve the user ID.
	userID := getUserID(r)

	// If getUserID(r) returns an empty string, the user is redirected because they are not authenticated.
	if userID == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// User is logged in, and no error, parse the form data (proceed with comment creation)
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Extract post ID from the URL path and the content from the form
	postID := extractPostID(r.URL.Path)
	content := r.Form.Get("commentContent")

	// Insert the comment into the database
	_, err = db.Exec(`
        INSERT INTO comments (id, post_id, user_id, content, created_at)
        VALUES (?, ?, ?, ?, ?)
    `, uuid.New().String(), postID, userID, content, time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect back to the home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Function processes POST request (like) from the html template
func likePostHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	if userID == "" { // Check if the user is logged in (based on the retrieved value)
		http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to the login page
		return
	}

	postID := extractPostID(r.URL.Path) // Retrieve post ID from the URL

	// Check if the user already disliked the post, reverse the interaction if true
	if hasUserInteractedWithPost(getUserID(r), postID, "dislike") {
		decreasePostDislikeCount(postID)
		removePostInteraction(getUserID(r), postID)
	} else if !hasUserInteractedWithPost(getUserID(r), postID, "like") {
		// Increment the like count and add the interaction only if the user has not liked the post before
		increasePostLikeCount(postID)
		addPostInteraction(getUserID(r), postID, "like")
	}

	// Redirect back to the home page with an anchor to the updated post
	http.Redirect(w, r, "/#post-"+postID, http.StatusSeeOther)
}

// Function extracts the post ID from the URL path
func extractPostID(path string) string {
	// Assuming the URL path is in the format "/post/{id}" or "/like/{id}" or "/dislike/{id}"
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// Boolean function initiates a database query of post_interactons table to check whether the user has previously interacted with the post
func hasUserInteractedWithPost(userID, postID, action string) bool {
	var count int
	err := db.QueryRow(`
        SELECT COUNT(*)
        FROM post_interactions
        WHERE user_id = ? AND post_id = ? AND action = ?
    `, userID, postID, action).Scan(&count)
	return err == nil && count > 0
}

// Function increments the like count in post table suing UPDATE statement
func increasePostLikeCount(postID string) {
	_, err := db.Exec(`
        UPDATE posts
        SET likes_count = likes_count + 1
        WHERE id = ?
    `, postID)
	if err != nil {
		log.Println(err)
	}
}

// Function reduces the like count (if greater than zero) with UPDATE command sent to posts table
func decreasePostLikeCount(postID string) {
	_, err := db.Exec(`
        UPDATE posts
        SET likes_count = likes_count - 1
        WHERE id = ? AND likes_count > 0
    `, postID)
	if err != nil {
		log.Println(err)
	}
}

// Function records (with INSERT INTO statement) the interaction (like or dislike action) in the post_interactions table
func addPostInteraction(userID, postID, action string) {
	_, err := db.Exec(`
        INSERT INTO post_interactions (user_id, post_id, action)
        VALUES (?, ?, ?)
    `, userID, postID, action)
	if err != nil {
		log.Println(err)
	}
}

// Function removes the previous interaction from post_interactons table using DELETE statement
func removePostInteraction(userID, postID string) {
	_, err := db.Exec(`
        DELETE FROM post_interactions
        WHERE user_id = ? AND post_id = ?
    `, userID, postID)
	if err != nil {
		log.Println(err)
	}
}

func dislikePostHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r) // Get the user ID
	if userID == "" {      // Check if the user is logged in (based on the retrieved userID)
		http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to the login page
		return
	}

	postID := extractPostID(r.URL.Path) // Retrieve post ID from the URL

	// Check if the user already liked the post, reverse the interaction if true
	if hasUserInteractedWithPost(getUserID(r), postID, "like") {
		decreasePostLikeCount(postID)
		removePostInteraction(getUserID(r), postID)
	} else if !hasUserInteractedWithPost(getUserID(r), postID, "dislike") {
		// Increment the dislike count and add the interaction only if the user has not disliked the post before
		increasePostDislikeCount(postID)
		addPostInteraction(getUserID(r), postID, "dislike")
	}

	// Redirect back to the home page with an anchor to the updated post
	http.Redirect(w, r, "/#post-"+postID, http.StatusSeeOther)
}

// Function increments the dislike count in post table suing UPDATE statement
func increasePostDislikeCount(postID string) {
	_, err := db.Exec(`
        UPDATE posts
        SET dislikes_count = dislikes_count + 1
        WHERE id = ?
    `, postID)
	if err != nil {
		log.Println(err)
	}
}

// Function reduces the dislike count (if greater than zero) with UPDATE command sent to posts table
func decreasePostDislikeCount(postID string) {
	_, err := db.Exec(`
        UPDATE posts
        SET dislikes_count = dislikes_count - 1
        WHERE id = ? AND dislikes_count > 0
    `, postID)
	if err != nil {
		log.Println(err)
	}
}

// Function is responsible for processing a request to like a comment.
func likeCommentHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve comment ID from the URL
	commentID := extractCommentID(r.URL.Path)

	// Check if the user previousy disliked the comment
	if hasUserInteractedWithComment(getUserID(r), commentID, "dislike") {
		decreaseCommentDislikeCount(commentID)
		removeCommentInteraction(getUserID(r), commentID)
		// Increment like count and add like interaction if the user hasn't already liked the comment
	} else if !hasUserInteractedWithComment(getUserID(r), commentID, "like") {
		increaseCommentLikeCount(commentID)
		addCommentInteraction(getUserID(r), commentID, "like")
	}

	// Redirect back to the home page with an anchor to the updated comment
	http.Redirect(w, r, "/#comment-"+commentID, http.StatusSeeOther)
}

// Function is responsible for processing a request to dislike a comment.
func dislikeCommentHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve comment ID from the URL
	commentID := extractCommentID(r.URL.Path)

	// Check if the user previously liked the comment.
	if hasUserInteractedWithComment(getUserID(r), commentID, "like") {
		decreaseCommentLikeCount(commentID)
		removeCommentInteraction(getUserID(r), commentID)
		// Increment dislike count and add dislike interaction if the user hasn't already disliked the comment
	} else if !hasUserInteractedWithComment(getUserID(r), commentID, "dislike") {
		increaseCommentDislikeCount(commentID)
		addCommentInteraction(getUserID(r), commentID, "dislike")
	}

	// Redirect back to the home page with an anchor to the updated comment
	http.Redirect(w, r, "/#comment-"+commentID, http.StatusSeeOther)
}

// Function extracts the post ID from the URL path
func extractCommentID(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// Function checks whether the user has previously interacted with the comment and returns true if the interaction exists.
func hasUserInteractedWithComment(userID, commentID, action string) bool {
	var count int
	err := db.QueryRow(`
        SELECT COUNT(*)
        FROM comment_interactions
        WHERE user_id = ? AND comment_id = ? AND action = ?
    `, userID, commentID, action).Scan(&count)
	return err == nil && count > 0
}

// Function increments like count in the comments table using SQL UPDATE statement
func increaseCommentLikeCount(commentID string) {
	_, err := db.Exec(`
        UPDATE comments
        SET likes_count = likes_count + 1
        WHERE id = ?
    `, commentID)
	if err != nil {
		log.Println(err)
	}
}

// Function reduces like count (if greater than zero) in the comments table using SQL UPDATE statement
func decreaseCommentLikeCount(commentID string) {
	_, err := db.Exec(`
        UPDATE comments
        SET likes_count = likes_count - 1
        WHERE id = ? AND likes_count > 0
    `, commentID)
	if err != nil {
		log.Println(err)
	}
}

// Function increments dislike count for the comment using SQL UPDATE statement
func increaseCommentDislikeCount(commentID string) {
	_, err := db.Exec(`
        UPDATE comments
        SET dislikes_count = dislikes_count + 1
        WHERE id = ?
    `, commentID)
	if err != nil {
		log.Println(err)
	}
}

// Function reduces dislike count (if greater than zero) for the comment using SQL UPDATE statement
func decreaseCommentDislikeCount(commentID string) {
	_, err := db.Exec(`
        UPDATE comments
        SET dislikes_count = dislikes_count - 1
        WHERE id = ? AND dislikes_count > 0
    `, commentID)
	if err != nil {
		log.Println(err)
	}
}

// Function inserts a new interaction (the like or dislike action) into the comment_interactions table
func addCommentInteraction(userID, commentID, action string) {
	_, err := db.Exec(`
        INSERT INTO comment_interactions (user_id, comment_id, action)
        VALUES (?, ?, ?)
    `, userID, commentID, action)
	if err != nil {
		log.Println(err)
	}
}

// Function removes user's interaction from comment_interactions table
func removeCommentInteraction(userID, commentID string) {
	_, err := db.Exec(`
        DELETE FROM comment_interactions
        WHERE user_id = ? AND comment_id = ?
    `, userID, commentID)
	if err != nil {
		log.Println(err)
	}
}

// Function queries the posts table to count the number of posts created by the user, grouped by the creation date
func getUserPostData(userID string) ([]string, []int, error) {
	rows, err := db.Query(`
        SELECT DATE(created_at), COUNT(*) 
        FROM posts 
        WHERE user_id = ? 
        GROUP BY DATE(created_at) 
        ORDER BY DATE(created_at)`, userID) // ensuring dates are returned in chronological order
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var dates []string
	var counts []int

	// Iterated over the results, and are appended the dates and post counts to two slices
	for rows.Next() {
		var date string
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			return nil, nil, err
		}
		dates = append(dates, date)
		counts = append(counts, count)
	}

	// dates and counts are returned for visualisation
	return dates, counts, nil
}

// Function receives the dates and counts and creates a chart for user posts activity
func userPostsChartHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	// Fetch data and check for errors
	dates, counts, err := getUserPostData(userID)
	if err != nil {
		http.Error(w, "Error fetching user post activity", http.StatusInternalServerError)
		return
	}

	// Format the data as a series of opts.LineData objects to be used in the line chart.
	data := make([]opts.LineData, len(counts)) // Initialise the slice with the right size.
	for i, v := range counts {                 // The loop fills the new slice with properly formatted data.
		data[i] = opts.LineData{Value: v}
	}

	// Creates line chart
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: "User Post Activity"}),
		charts.WithXAxisOpts(opts.XAxis{Name: "Date"}),
		charts.WithYAxisOpts(opts.YAxis{
			Name:        "Posts",
			Min:         0, // Ensure Y-axis starts at 0
			MinInterval: 1, // Only show integer intervals
			Type:        "value",
			AxisLabel:   &opts.AxisLabel{Formatter: "{value}"}, // Forces integer display
		}),
	)
	line.SetXAxis(dates).AddSeries("Posts", data)

	// Render the chart
	w.Header().Set("Content-Type", "text/html")
	page := components.NewPage()
	page.AddCharts(line)
	page.Render(w)
}

// Retrieve the number of comments has been made on user posts on each date.
func getCommentsDataOnUserPosts(userID string) ([]string, []int) {
	rows, err := db.Query(`
        SELECT DATE(created_at) as date, COUNT(*) 
        FROM comments 
        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?) 
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)`, userID)
	if err != nil {
		log.Println("Error fetching user comment data:", err)
		return nil, nil
	}
	defer rows.Close()

	var dates []string
	var counts []int

	// Iterated over the results, and are appended the dates and post counts to two slices
	for rows.Next() {
		var date string
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			log.Println("Error scanning user comment data:", err)
			continue
		}
		dates = append(dates, date)
		counts = append(counts, count)
	}

	// dates and counts are returned for visualisation
	return dates, counts
}

func commentsOnUserPostsChartHandler(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r) // Get user ID from session or request

	// Fetch data
	dates, counts := getCommentsDataOnUserPosts(userID)

	// Create chart
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: "Comment Activity on Your Posts"}),
		charts.WithXAxisOpts(opts.XAxis{Name: "Date"}),
		charts.WithYAxisOpts(opts.YAxis{
			Name:        "Comments",
			Min:         0,
			MinInterval: 1,
			Type:        "value",
			AxisLabel:   &opts.AxisLabel{Formatter: "{value}"},
		}),
	)

	// Format the data as a series of opts.LineData objects to be used in the line chart.
	data := make([]opts.LineData, len(counts)) // Initialise the slice with the right size.
	for i, v := range counts {                 // The loop fills the new slice with properly formatted data.
		data[i] = opts.LineData{Value: v}
	}

	line.SetXAxis(dates).AddSeries("Comments", data)

	// Render the chart
	w.Header().Set("Content-Type", "text/html")
	page := components.NewPage()
	page.AddCharts(line)
	page.Render(w)
}
