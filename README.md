BSc Data Science and Computing project

## To run the app:
###
    $go run main.go

    To run with docker:
    $docker image build -t my-forum-app .  
    $docker container run -p 8080:8080 my-forum-app

    Open your web browser and navigate to http://localhost:8080.
    Register user > Login > ...

###
This project helps to learn about:
    The basics of web:
        HTML
        HTTP
        Sessions and cookies
    Using and setting up Docker
        Containerizing an application
        Compatibility/Dependency
        Creating images
    SQL language
        Manipulation of databases
    The basics of encryption

###
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