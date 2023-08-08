package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"golang.org/x/crypto/bcrypt"
)

func connectMongoDB() *mongo.Client {
	var config Config

	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".") // Look for the config file in the current directory
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("Error reading config file:", err)
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		log.Fatal("Error unmarshaling config:", err)
	}

	// Use the SetServerAPIOptions() method to set the Stable API version to 1
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(config.MongoDB.URI).SetServerAPIOptions(serverAPI)
	// Create a new client and connect to the server
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		panic(err)
	}

	// insertNewBookFromFile(client)

	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

	return client
}

type Config struct {
	MongoDB struct {
		URI string `mapstructure:"uri"`
	} `mapstructure:"mongodb"`
}

// field names need to start with capitol letter to be an exported field
// “ to serialize to json
type book struct {
	ID                primitive.ObjectID	`json:"_id,omitempty" bson:"_id,omitempty"`
	Title             string   				`json:"title" bson:"title"`
	Author            string   				`json:"author" bson:"author"`
	ISBN              string   				`json:"isbn" bson:"isbn"`
	Genre             []string 				`json:"genre" bson:"genre"`
	IsCheckedOut      bool     				`json:"is_checked_out" bson:"is_checked_out"`
	CheckedOutDate    int64    				`json:"checked_out_date" bson:"checked_out_date"`
	ReturnDate  	  int64    				`json:"return_date" bson:"return_date"`
	CheckedOutID      string				`json:"checked_out_id" bson:"checked_out_id"`
	CheckedOutHistory []string 				`json:"checked_out_history" bson:"checked_out_history"`
}

type user struct {
	ID              primitive.ObjectID		`json:"_id,omitempty" bson:"_id,omitempty"`
	FirstName		string					`json:"first_name" bson:"first_name"`
	LastName	  	string					`json:"last_name" bson:"last_name"`
	Username	  	string					`json:"username" bson:"username"`
	Password		string					`json:"password" bson:"password"`
	Email			string					`json:"email" bson:"email"`
	MaxCheckOut   	int						`json:"max_check_out" bson:"max_check_out"`
	CheckOutList  	[]string 				`json:"check_out_list" bson:"check_out_list"`
}

func (b *book) setDefaults() {
	b.IsCheckedOut = false
	b.CheckedOutDate = -1
	b.ReturnDate = -1
	b.CheckedOutID = ""
	b.CheckedOutHistory = []string{}
}

func copyUpdatesForReturn(updates bson.M, s interface{}) bson.M {
	data, err := bson.Marshal(s)
	if err != nil {
		fmt.Println("Error Marshalling struct")
		return nil
	}

	var result bson.M
	err = bson.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshalling bson byte slice")
		return nil
	}

	for key, value := range updates {
		result[key] = value
	}

	return result
}

func checkInBook(c *gin.Context, client *mongo.Client) {
	booksCollection := client.Database("library").Collection("books")
	usersCollection := client.Database("library").Collection("users")
	
	// Get book from body
	var curBook book

	if err := c.BindJSON(&curBook); err != nil {
		return
	}

	ctx := context.Background()


	// Get book from db
	bookFilter := bson.M{"_id": curBook.ID}

	var dbBook book
	err := booksCollection.FindOne(ctx, bookFilter).Decode(&dbBook)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Book does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	if !dbBook.IsCheckedOut {
		c.IndentedJSON(http.StatusConflict, gin.H{"error": "Book wasn't checked out. No need to check in"})
		return
	}

	bookUpdate := bson.M{"$set": bson.M{"is_checked_out": false}}
	
	updateBookResult, err := booksCollection.UpdateOne(ctx, bookFilter, bookUpdate)

	if updateBookResult.ModifiedCount > 0 {
		fmt.Println("Book updated successfully!")

	} else {
		fmt.Println("Book not found or no changes made.")
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Document not  found or no changes made."})
		return
	}

	userID, err := primitive.ObjectIDFromHex(dbBook.CheckedOutID)
	if err != nil{
		fmt.Println("Error:", err)
		return
	}
	userFilter := bson.M{"_id": userID}

	var dbUser user
	err = usersCollection.FindOne(ctx, userFilter).Decode(&dbUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "User no longer exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	userCheckOutList := dbUser.CheckOutList
	var updatedList []string

	for _, item := range userCheckOutList {
		if item != dbBook.ID.Hex(){
			updatedList = append(updatedList, item)
		}
	}

	userUpdate := bson.M{"$set": bson.M{"check_out_list": updatedList}}

	updateUserResult, err := usersCollection.UpdateOne(ctx, userFilter, userUpdate)

	if updateUserResult.ModifiedCount > 0 {
		fmt.Println("User updated successfully!")

	} else {
		fmt.Println("User not found or no changes made.")
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Document not  found or no changes made."})
		return
	}


	c.IndentedJSON(http.StatusOK, gin.H{"success": "Book checked in"})
	return
}

func checkOutBook(c *gin.Context, client *mongo.Client) {
	booksCollection := client.Database("library").Collection("books")
	usersCollection := client.Database("library").Collection("users")
	
	// Get book from body
	var curBook book

	if err := c.BindJSON(&curBook); err != nil {
		return
	}

	ctx := context.Background()

	// Get user from db
	curUsername, err := c.Cookie("username")

	// If there's an error or the cookie value is not "true", the user is not logged in
	if err != nil || curUsername == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in"})
		c.Abort()
		return
	}

	userFilter := bson.M{"username": curUsername}

	var dbUser user
	err = usersCollection.FindOne(ctx, userFilter).Decode(&dbUser)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "User does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	if len(dbUser.CheckOutList) >= dbUser.MaxCheckOut {
		c.JSON(http.StatusConflict, gin.H{"error": "User has reached check out limit"})
		return
	}

	// Get book from db
	bookFilter := bson.M{"_id": curBook.ID}

	var dbBook book
	err = booksCollection.FindOne(ctx, bookFilter).Decode(&dbBook)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Book does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	if dbBook.IsCheckedOut {
		c.IndentedJSON(http.StatusConflict, gin.H{"error": "Book is current checked out. Should become available " + time.Unix(dbBook.ReturnDate, 0).Format("January 2, 2006")})
		return
	}

	bookBson := bson.M{"is_checked_out": true, "checked_out_date": time.Now().Unix(), "return_date": time.Now().Add(time.Hour * 168).Unix(), 
	"checked_out_id": dbUser.ID.Hex(), "checked_out_history": append(dbBook.CheckedOutHistory, dbUser.ID.Hex())}
	bookUpdate := bson.M{"$set": bookBson}
	
	updateBookResult, err := booksCollection.UpdateOne(ctx, bookFilter, bookUpdate)

	if updateBookResult.ModifiedCount > 0 {
		fmt.Println("Book updated successfully!")

	} else {
		fmt.Println("Book not found or no changes made.")
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Document not  found or no changes made."})
		return
	}

	userBson := bson.M{"check_out_list": append(dbUser.CheckOutList, dbBook.ID.Hex())}
	userUpdate := bson.M{"$set": userBson}

	updateUserResult, err := usersCollection.UpdateOne(ctx, userFilter, userUpdate)

	if updateUserResult.ModifiedCount > 0 {
		fmt.Println("User updated successfully!")

	} else {
		fmt.Println("User not found or no changes made.")
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Document not  found or no changes made."})
		return
	}

	updatedDbBookBson := copyUpdatesForReturn(bookBson, dbBook)
	updatedDbUserBson := copyUpdatesForReturn(userBson, dbUser)
	c.IndentedJSON(http.StatusOK, gin.H{"book": updatedDbBookBson, "user": updatedDbUserBson})
	return
}

// GET Request functions
func getAllBooksHandler(c *gin.Context, client *mongo.Client) {
	fmt.Println("getAllBooksHandler func")
	// Access the "library" database and "books" collection
	collection := client.Database("library").Collection("books")

	// Set up an empty slice to store the results
	var results []bson.M

	// Perform the query to retrieve all documents
	ctx := context.TODO()
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	// Iterate through the cursor to get the results
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var result bson.M
		if err := cursor.Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding document"})
			return
		}
		results = append(results, result)
	}

	// Handle any errors that occurred during cursor iteration
	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error during cursor iteration"})
		return
	}

	// Return the retrieved documents in the response
	c.JSON(http.StatusOK, results)
}

func requireBasicAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, password, hasAuth := c.Request.BasicAuth()

		if hasAuth && user == "admin" && password == "admin" {
            c.Next()
        } else {
            c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
            c.AbortWithStatus(http.StatusUnauthorized)
        }
	}
}

// POST request funcitons
func registerNewUser(c *gin.Context, client *mongo.Client) {
	collection := client.Database("library").Collection("users")
	
	var newUser user

	if err := c.BindJSON(&newUser); err != nil {
		return
	}

	ctx := context.Background()

	filter := bson.M{"username": newUser.Username}

	var user user
	err := collection.FindOne(ctx, filter).Decode(&user)

	if err == mongo.ErrNoDocuments {
		
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Error hashing password:", err)
			return
		}

		newUser.Password = string(hashedPassword)
		
		// Insert the document into the collection
		insertResult, err := collection.InsertOne(ctx, newUser)
		if err != nil {
			log.Fatal("Failed to insert document:", err)
		}

		newUser.ID = insertResult.InsertedID.(primitive.ObjectID)
		setUserCookies(c, newUser)
		fmt.Println("New User Created and logged in!")
		c.IndentedJSON(http.StatusCreated, newUser)
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	} else if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists."})
		return
	}	
}

func requireLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Retrieve the "loggedIn" cookie
		loggedIn, err := c.Cookie("loggedIn")

		// If there's an error or the cookie value is not "true", the user is not logged in
		if err != nil || loggedIn != "true" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// The user is logged in, continue with the next handler
		c.Next()
	}	
}

func setUserCookies(c *gin.Context, curUser user) {
	c.SetCookie("loggedIn", "true", 3600, "/", "", false, false)
	c.SetCookie("username", curUser.Username, 3600, "/", "", false, false)
}

func login(c *gin.Context, client *mongo.Client) {
	fmt.Println("login func")
	collection := client.Database("library").Collection("users")
	
	var tempUser user

	if err := c.BindJSON(&tempUser); err != nil {
		return
	}

	ctx := context.Background()

	filter := bson.M{"username": tempUser.Username}

	var user user
	err := collection.FindOne(ctx, filter).Decode(&user)

	if err == mongo.ErrNoDocuments {
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Username not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	} else if err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tempUser.Password)); err == nil {
			setUserCookies(c, tempUser)

			c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
			return
		} else if err == bcrypt.ErrMismatchedHashAndPassword {
			c.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "Passwords don't match"})
			return	
		} else {
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Internal Servier Error"})
			return
		}
	}	
}

func logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func insertNewBook(c *gin.Context, client *mongo.Client) {
	database := client.Database("library")
	collection := database.Collection("books")

	var book book

	if err := c.BindJSON(&book); err != nil {
		return
	}

	ctx := context.Background()


	book.setDefaults()
	fmt.Printf("Title: %s\n", book.Title)
	fmt.Printf("Author: %s\n", book.Author)
	fmt.Printf("Genre: %v\n", book.Genre)
	fmt.Printf("ISBN: %s\n\n", book.ISBN)

	// Insert the document into the collection
	insertResult, err := collection.InsertOne(ctx, book)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert book"})
		return
	}

	book.ID = insertResult.InsertedID.(primitive.ObjectID)
	c.IndentedJSON(http.StatusOK, book)
	return
}

func insertNewBooks(c *gin.Context, client *mongo.Client) {
	database := client.Database("library")
	collection := database.Collection("books")


	var books []book

	if err := c.BindJSON(&books); err != nil {
		return
	}

	ctx := context.Background()

	for _, book := range books {
		book.setDefaults()
		fmt.Printf("Title: %s\n", book.Title)
		fmt.Printf("Author: %s\n", book.Author)
		fmt.Printf("Genre: %v\n", book.Genre)
		fmt.Printf("ISBN: %s\n\n", book.ISBN)

		// Insert the document into the collection
		insertResult, err := collection.InsertOne(ctx, book)
		if err != nil {
			c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert new book"})
			return
		}
		book.ID = insertResult.InsertedID.(primitive.ObjectID)
		c.IndentedJSON(http.StatusOK, book)
	}
}

// Middleware to clear all cookies on startup
func clearCookies() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the list of cookies from the request
		cookies := c.Request.Cookies()

		// Delete each cookie by setting MaxAge to a negative value
		for _, cookie := range cookies {
			fmt.Println("Clearing cookie ", cookie.Name)
			c.SetCookie(cookie.Name, "", -1, "/", "", false, true)
		}

		// Continue with the next handler
		c.Next()
	}
}

func getBookByID(c *gin.Context, client *mongo.Client) {
	fmt.Println("getBookByID func")
	database := client.Database("library")
	collection := database.Collection("books")

	bookID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil{
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "invalid book ID or misspelled endpoint"})
		return
	}

	ctx := context.Background()

	filter := bson.M{"_id": bookID}

	var book book
	err = collection.FindOne(ctx, filter).Decode(&book)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "Book does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	c.IndentedJSON(http.StatusOK, book)
	return
}

func getUserByID(c *gin.Context, client *mongo.Client) {
	database := client.Database("library")
	collection := database.Collection("users")

	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil{
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "invalid user ID or misspelled endpoint"})
		return
	}

	ctx := context.Background()

	filter := bson.M{"_id": userID}

	var user user
	err = collection.FindOne(ctx, filter).Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "User does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	c.IndentedJSON(http.StatusOK, user)
	return
}

func getCheckedOutBooks(c *gin.Context, client *mongo.Client) {
	fmt.Println("getCheckedOutBooks func")
	database := client.Database("library")
	collection := database.Collection("books")

	ctx := context.Background()
	filter := bson.M{"is_checked_out": true}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	defer cursor.Close(ctx)

	var checkedOutBooks []book
		for cursor.Next(context.Background()) {
			var book book
			if err := cursor.Decode(&book); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding document"})
				return
			}
			checkedOutBooks = append(checkedOutBooks, book)
		}

		c.JSON(http.StatusOK, checkedOutBooks)
}

func getOverdueBooks(c *gin.Context, client *mongo.Client) {
	database := client.Database("library")
	collection := database.Collection("books")

	ctx := context.Background()
	filter := bson.M{"is_checked_out": true}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	defer cursor.Close(ctx)

	var overdueBooks []book
		for cursor.Next(context.Background()) {
			var book book
			if err := cursor.Decode(&book); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decoding document"})
				return
			}

			dueDate := book.ReturnDate
			todayDate := time.Now().Unix()

			if todayDate >= dueDate {
				overdueBooks = append(overdueBooks, book)
			}
		}

		c.JSON(http.StatusOK, overdueBooks)
}

func deleteUser(c *gin.Context, client *mongo.Client) {
	database := client.Database("library")
	collection := database.Collection("users")

	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil{
		c.IndentedJSON(http.StatusNotFound, gin.H{"error": "invalid user ID or misspelled endpoint"})
		return
	}

	ctx := context.TODO()

	filter := bson.M{"_id": userID}

	deleteResult, err := collection.DeleteOne(ctx, filter)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": "User does not exist"})
			return
		}
	
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the collection"})
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"success": userID.Hex() + " deleted. Count: " + strconv.FormatInt(deleteResult.DeletedCount, 10)})
	return
}

func main() {
	client := connectMongoDB()
	// clearCookies()

	router := gin.Default()

	router.GET("/login", func(c *gin.Context){login(c, client)})
	router.GET("/books", func(c *gin.Context){getAllBooksHandler(c, client)})
	router.GET("/books/:id", func(c *gin.Context){getBookByID(c, client)})
	router.GET("/books/checkedOut", func(c *gin.Context){getCheckedOutBooks(c, client)})
	router.GET("/books/overdue", func(c *gin.Context){getOverdueBooks(c, client)})
	router.GET("/users/:id", func(c *gin.Context){getUserByID(c, client)})

	router.POST("/users/newUser", requireBasicAuth(), func(c *gin.Context){registerNewUser(c, client)})
	router.POST("/books/newBook", requireBasicAuth(), func(c *gin.Context){insertNewBook(c, client)})
	router.POST("/books/newBooks", requireBasicAuth(), func(c *gin.Context){insertNewBooks(c, client)})

	router.PATCH("/books/checkout", func(c *gin.Context){checkOutBook(c, client)})
	router.PATCH("/books/checkin", func(c *gin.Context){checkInBook(c, client)})

	router.DELETE("/users/:id", requireBasicAuth(), func(c *gin.Context){deleteUser(c, client)})

	logoutGroup := router.Group("/logout")
	logoutGroup.Use(requireLogin(), clearCookies())
	logoutGroup.GET("/", logout)

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
	})

	router.Run("localhost:8080")
}
