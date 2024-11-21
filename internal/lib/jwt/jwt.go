package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"sso/internal/domain/models"
	"time"
)

type UserInfo struct {
	UserID int
	Email  string
}

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(tokenString string, app models.App) (UserInfo, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})

	if err != nil {
		return UserInfo{}, err
	}

	if !token.Valid {
		return UserInfo{}, err
	}

	claims := token.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	userID := int(claims["uid"].(float64))
	usr := UserInfo{UserID: userID, Email: email}
	return usr, nil
}
