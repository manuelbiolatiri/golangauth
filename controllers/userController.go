package controllers

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-playground/validator"
	"github.com/gofiber/fiber/v2"
	"github.com/manuelbiolatiri/golangauthtest/config"
	helper "github.com/manuelbiolatiri/golangauthtest/helpers"
	"github.com/manuelbiolatiri/golangauthtest/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var validate = validator.New()

//HashPassword is used to encrypt the password before it is stored in the DB
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}

	return string(bytes)
}

//VerifyPassword checks the input password while verifying it with the passward in the DB.
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("login or passowrd is incorrect")
		check = false
	}

	return check, msg
}

func SignUp(c *fiber.Ctx) error {
	userCollection := config.MI.DB.Collection("users")

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var user models.User

	if err := c.BodyParser(&user); err != nil {
		log.Println(err)
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"message": "Failed to parse body",
			"error":   err,
		})
	}

	validationErr := validate.Struct(user)

	if validationErr != nil {
		error := validationErr.Error()

		log.Println(error)
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"message": "validationErr",
			"error":   error,
		})
	}

	count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	defer cancel()

	if err != nil {
		log.Panic(err)

		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": "error occured while checking for the email",
			"error":   err,
		})
	}

	password := HashPassword(*user.Password)
	user.Password = &password

	count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
	defer cancel()

	if err != nil {
		log.Panic(err)

		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": "error occured while checking for the phone number",
			"error":   err,
		})
	}

	if count > 0 {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": "this email or phone number already exists",
			"error":   nil,
		})
	}

	user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)
	user.Token = &token
	user.Refresh_token = &refreshToken

	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := fmt.Sprintf("User item was not created")

		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": msg,
			"error":   insertErr,
		})
	}
	defer cancel()

	return c.Status(500).JSON(fiber.Map{
		"success": true,
		"message": "successful",
		"data":    resultInsertionNumber,
	})
}

func Login(c *fiber.Ctx) error {
	userCollection := config.MI.DB.Collection("users")

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var user models.User
	var foundUser models.User

	if err := c.BodyParser(&user); err != nil {
		log.Println(err)
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"message": "Failed to parse body",
			"error":   err,
		})
	}

	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
	defer cancel()
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"success": false,
			"message": "login or passowrd is incorrect",
			"error":   err,
		})
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	defer cancel()

	if passwordIsValid != true {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": msg,
			"error":   msg,
		})
	}

	if foundUser.Email == nil {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": "user not found",
			"error":   msg,
		})
	}
	token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)

	helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)

	err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
			"error":   err,
		})
	}

	return c.Status(200).JSON(fiber.Map{
		"success": true,
		"message": "successfully",
		"data":    foundUser,
	})
}
