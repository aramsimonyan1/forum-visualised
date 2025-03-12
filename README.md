# BSc Data Science and Computing project

## Author: Aram Simonyan (May 2025)
###
This project explores the development of a forum application designed to enhance user engagement and provide insightful activity visualisations. The primary objective is to create a user-friendly and scalable platform where participants can interact through discussions while gaining valuable insights into their activity patterns.

    The Go programming language is used for back-end development.
    The front-end of the forum is developed using HTML5 and CSS.
    The Golang library go-echarts is used for data visualisation.
    SQLite is used as the database management system.
    Bycrypt hashing function and go-password-validator package are used to ensure security in authentication process.
    Application containerisation with Docker simplifies dependency management and cross-environment deployment.

## To run the app:
### Type in terminal 
    $go run main.go   
    (You may wait a few seconds and allow the firewall to enable some features of main.exe on public and private networks)

    To run with docker:
    $docker image build -t my-forum-app .  
    $docker container run -p 8080:8080 my-forum-app

    Open your web browser and navigate to http://localhost:8080.
    The forum webpage should now be able to Register or Login to the platform.


### List of functions:

func initDB()
func main()
func getUserID(r *http.Request) string 
func invalidateSessionsForUser(email string) error
func registerHandler(w http.ResponseWriter, r *http.Request)
func emailExists(email string) bool
func loginHandler(w http.ResponseWriter, r *http.Request)
func logoutHandler(w http.ResponseWriter, r *http.Request)
func getPostsFromDatabase(categoryFilter string) ([]Post, error) 
func getCommentsForPost(postID string) ([]Comment, error) 
func homeHandler(w http.ResponseWriter, r *http.Request)
func getPostsByUser(userID string) ([]Post, error)
func getLikedPosts(userID string) ([]Post, error) 
func createPostHandler(w http.ResponseWriter, r *http.Request)
func categoryFilterHandler(w http.ResponseWriter, r *http.Request)
func addCommentHandler(w http.ResponseWriter, r *http.Request)
func viewPostHandler(w http.ResponseWriter, r *http.Request)
func likePostHandler(w http.ResponseWriter, r *http.Request)
func hasUserInteractedWithPost(userID, postID, action string) bool 
func increasePostLikeCount(postID string)
func decreasePostLikeCount(postID string)
func addPostInteraction(userID, postID, action string) 
func removePostInteraction(userID, postID string)
func dislikePostHandler(w http.ResponseWriter, r *http.Request)
func increasePostDislikeCount(postID string) 
func decreasePostDislikeCount(postID string)
func extractPostID(path string) string 
func likeCommentHandler(w http.ResponseWriter, r *http.Request) 
func dislikeCommentHandler(w http.ResponseWriter, r *http.Request)
func extractCommentID(path string) string
func hasUserInteractedWithComment(userID, commentID, action string) bool 
func increaseCommentLikeCount(commentID string) 
func decreaseCommentLikeCount(commentID string)
func increaseCommentDislikeCount(commentID string) 
func decreaseCommentDislikeCount(commentID string) 
func addCommentInteraction(userID, commentID, action string) 
func removeCommentInteraction(userID, commentID string) 
func splitCategories(categoriesString string) []string
func getPostByID(postID string) (*Post, error)
func getUserPostData(userID string) (map[string]int, error)
func userPostChartHandler(w http.ResponseWriter, r *http.Request) 
func getUserCommentData(userID string) ([]string, []int)
func userCommentChartHandler(w http.ResponseWriter, r *http.Request)