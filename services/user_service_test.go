package services

import (
	"errors"
	"fmt"
	"github.com/muchlist/auth_service_go/domains/users"
	"github.com/muchlist/erru_utils_go/rest_err"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"testing"
	"time"
)

var (
	getUserByIDFunction                func(userID primitive.ObjectID) (*users.UserResponse, rest_err.APIError)
	getUserByEmailFunction             func(email string) (*users.UserResponse, rest_err.APIError)
	getUserByEmailWithPasswordFunction func(email string) (*users.User, rest_err.APIError)
	insertUserFunction                 func(user users.UserRequest) (*string, rest_err.APIError)
	findUserFunction                   func() (users.UserResponseList, rest_err.APIError)
	checkEmailAvailableFunction        func(email string) (bool, rest_err.APIError)
	editUserFunction                   func(userEmail string, userRequest users.UserEditRequest) (*users.UserResponse, rest_err.APIError)
	deleteUserFunction                 func(userEmail string) rest_err.APIError
	putAvatarFunction                  func(email string, avatar string) (*users.UserResponse, rest_err.APIError)
	changePasswordFunction             func(data users.UserChangePasswordRequest) rest_err.APIError
)

func init() {
	//disini letak mockingnya, pada code asli interface di isi oleh Dao User
	//pada test di isi oleh usersDaoMock yang mengimplementasi semua Method interface
	users.UserDao = &usersDaoMock{}
}

type usersDaoMock struct{}

func (u *usersDaoMock) GetUserByID(userID primitive.ObjectID) (*users.UserResponse, rest_err.APIError) {
	return getUserByIDFunction(userID)
}

func (u *usersDaoMock) GetUserByEmail(email string) (*users.UserResponse, rest_err.APIError) {
	return getUserByEmailFunction(email)
}

func (u *usersDaoMock) GetUserByEmailWithPassword(email string) (*users.User, rest_err.APIError) {
	return getUserByEmailWithPasswordFunction(email)
}

func (u *usersDaoMock) InsertUser(user users.UserRequest) (*string, rest_err.APIError) {
	return insertUserFunction(user)
}

func (u *usersDaoMock) FindUser() (users.UserResponseList, rest_err.APIError) {
	return findUserFunction()
}

func (u *usersDaoMock) CheckEmailAvailable(email string) (bool, rest_err.APIError) {
	return checkEmailAvailableFunction(email)
}

func (u *usersDaoMock) EditUser(userEmail string, userRequest users.UserEditRequest) (*users.UserResponse, rest_err.APIError) {
	return editUserFunction(userEmail, userRequest)
}

func (u *usersDaoMock) DeleteUser(userEmail string) rest_err.APIError {
	return deleteUserFunction(userEmail)
}

func (u *usersDaoMock) PutAvatar(email string, avatar string) (*users.UserResponse, rest_err.APIError) {
	return putAvatarFunction(email, avatar)
}

func (u *usersDaoMock) ChangePassword(data users.UserChangePasswordRequest) rest_err.APIError {
	return changePasswordFunction(data)
}

//--------------------------------------------------------------------------

func TestUserService_GetUser(t *testing.T) {
	getUserByIDFunction = func(userID primitive.ObjectID) (*users.UserResponse, rest_err.APIError) {
		return &users.UserResponse{
			ID:        primitive.NewObjectID(),
			Email:     "whois.muchlis@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   true,
			Avatar:    "",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	objectID := primitive.NewObjectID()
	user, err := UserService.GetUser(objectID)

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", user.Name)
	assert.Equal(t, "whois.muchlis@gmail.com", user.Email)
	assert.Equal(t, true, user.IsAdmin)
}

func TestUserService_GetUser_NoUserFound(t *testing.T) {
	getUserByIDFunction = func(userID primitive.ObjectID) (*users.UserResponse, rest_err.APIError) {
		apiErr := rest_err.NewNotFoundError(fmt.Sprintf("User dengan ID %v tidak ditemukan", userID.Hex()))
		return nil, apiErr
	}

	objectID := primitive.NewObjectID()
	user, err := UserService.GetUser(objectID)

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, fmt.Sprintf("User dengan ID %v tidak ditemukan", objectID.Hex()), err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func TestUserService_GetUserByEmail_Found(t *testing.T) {
	getUserByEmailFunction = func(email string) (*users.UserResponse, rest_err.APIError) {
		return &users.UserResponse{
			ID:        primitive.NewObjectID(),
			Email:     "whois.muchlis@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   true,
			Avatar:    "",
			Timestamp: time.Now().Unix(),
		}, nil
	}

	user, err := UserService.GetUserByEmail("whois.muchlis@gmail.com")

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", user.Name)
	assert.Equal(t, "whois.muchlis@gmail.com", user.Email)
	assert.Equal(t, true, user.IsAdmin)
}

func TestUserService_GetUserByEmail_NotFound(t *testing.T) {
	getUserByEmailFunction = func(email string) (*users.UserResponse, rest_err.APIError) {
		apiErr := rest_err.NewNotFoundError(fmt.Sprintf("User dengan Email %s tidak ditemukan", email))
		return nil, apiErr
	}

	user, err := UserService.GetUserByEmail("emailsembarang@gmail.com")

	assert.Nil(t, user)
	assert.NotNil(t, err)
	assert.Equal(t, "User dengan Email emailsembarang@gmail.com tidak ditemukan", err.Message())
	assert.Equal(t, http.StatusNotFound, err.Status())
}

func TestUserService_FindUsers(t *testing.T) {
	findUserFunction = func() (users.UserResponseList, rest_err.APIError) {
		return users.UserResponseList{
			users.UserResponse{
				ID:        primitive.NewObjectID(),
				Email:     "whois.muchlis@gmail.com",
				Name:      "Muchlis",
				IsAdmin:   true,
				Avatar:    "",
				Timestamp: time.Now().Unix(),
			},
		}, nil
	}

	usersResult, err := UserService.FindUsers()

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", usersResult[0].Name)
	assert.Equal(t, "whois.muchlis@gmail.com", usersResult[0].Email)
}

func TestUserService_FindUsers_errorDatabase(t *testing.T) {
	findUserFunction = func() (users.UserResponseList, rest_err.APIError) {
		apiErr := rest_err.NewInternalServerError("Database error", nil)
		return users.UserResponseList{}, apiErr
	}

	usersResult, err := UserService.FindUsers()

	assert.NotNil(t, err)
	assert.Equal(t, users.UserResponseList(nil), usersResult)
	assert.Equal(t, "Database error", err.Message())
	assert.Equal(t, http.StatusInternalServerError, err.Status())
}

func TestUserService_InsertUser_Success(t *testing.T) {
	checkEmailAvailableFunction = func(email string) (bool, rest_err.APIError) {
		return true, nil
	}
	insertUserFunction = func(user users.UserRequest) (*string, rest_err.APIError) {
		id := "5f969f62259eae481fb0e856"
		return &id, nil
	}

	userInput := users.UserRequest{
		Email:     "whowho@gmail.com",
		Name:      "Muchlis",
		IsAdmin:   true,
		Avatar:    "",
		Password:  "Password",
		Timestamp: time.Now().Unix(),
	}

	insertedId, err := UserService.InsertUser(userInput)

	assert.Nil(t, err)
	assert.Equal(t, "5f969f62259eae481fb0e856", *insertedId)
}

func TestUserService_InsertUser_EmailNotAvailable(t *testing.T) {
	checkEmailAvailableFunction = func(email string) (bool, rest_err.APIError) {
		apiErr := rest_err.NewBadRequestError("Email tidak tersedia")
		return false, apiErr
	}

	userInput := users.UserRequest{}

	insertedId, err := UserService.InsertUser(userInput)

	assert.Nil(t, insertedId)
	assert.NotNil(t, err)
	assert.Equal(t, "Email tidak tersedia", err.Message())
	assert.Equal(t, 400, err.Status())
}

func TestUserService_InsertUser_DBError(t *testing.T) {
	checkEmailAvailableFunction = func(email string) (bool, rest_err.APIError) {
		return true, nil
	}
	insertUserFunction = func(user users.UserRequest) (*string, rest_err.APIError) {
		apiErr := rest_err.NewInternalServerError("Gagal menyimpan user ke database", errors.New("db error"))
		return nil, apiErr
	}
	userInput := users.UserRequest{}

	insertedId, err := UserService.InsertUser(userInput)

	assert.Nil(t, insertedId)
	assert.NotNil(t, err)
	assert.Equal(t, "Gagal menyimpan user ke database", err.Message())
	assert.Equal(t, 500, err.Status())
}

func TestUserService_EditUser(t *testing.T) {
	editUserFunction = func(userEmail string, userRequest users.UserEditRequest) (*users.UserResponse, rest_err.APIError) {
		return &users.UserResponse{
			ID:        primitive.ObjectID{},
			Email:     "whowho@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "",
			Timestamp: 0,
		}, nil
	}

	userResponse, err := UserService.EditUser("whowho@gmail.com", users.UserEditRequest{
		Name:            "Muchlis",
		IsAdmin:         false,
		TimestampFilter: 0,
	})

	assert.Nil(t, err)
	assert.Equal(t, "Muchlis", userResponse.Name)
}

func TestUserService_EditUser_TimeStampNotmatch(t *testing.T) {
	editUserFunction = func(userEmail string, userRequest users.UserEditRequest) (*users.UserResponse, rest_err.APIError) {
		return nil, rest_err.NewBadRequestError("User tidak diupdate karena ID atau timestamp tidak valid")
	}

	userResponse, err := UserService.EditUser("whowho@gmail.com", users.UserEditRequest{
		Name:            "Muchlis",
		IsAdmin:         false,
		TimestampFilter: 0,
	})

	assert.Nil(t, userResponse)
	assert.NotNil(t, err)
	assert.Equal(t, "User tidak diupdate karena ID atau timestamp tidak valid", err.Message())
	assert.Equal(t, 400, err.Status())
}

func TestUserService_DeleteUser(t *testing.T) {
	deleteUserFunction = func(userEmail string) rest_err.APIError {
		return nil
	}

	err := UserService.DeleteUser("whowho@gmail.com")
	assert.Nil(t, err)
}

func TestUserService_DeleteUser_Failed(t *testing.T) {
	deleteUserFunction = func(userEmail string) rest_err.APIError {
		return rest_err.NewBadRequestError("User gagal dihapus, dokumen tidak ditemukan")
	}

	err := UserService.DeleteUser("whowho@gmail.com")
	assert.NotNil(t, err)
	assert.Equal(t, "User gagal dihapus, dokumen tidak ditemukan", err.Message())
}

func TestUserService_Login(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		return &users.User{
			ID:        primitive.ObjectID{},
			Email:     "whowho@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "",
			HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
			Timestamp: 0,
		}, nil
	}

	userRequest := users.UserLoginRequest{
		Email:    "whowho@gmail.com",
		Password: "Password",
	}
	userResult, err := UserService.Login(userRequest)

	assert.Nil(t, err)
	assert.NotNil(t, userRequest)
	assert.Equal(t, "Muchlis", userResult.Name)
	assert.NotEmpty(t, userResult.AccessToken)
}

func TestUserService_Login_WrongPassword(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		return &users.User{
			ID:        primitive.ObjectID{},
			Email:     "whowho@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "",
			HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
			Timestamp: 0,
		}, nil
	}

	userRequest := users.UserLoginRequest{
		Email:    "whowho@gmail.com",
		Password: "salahPassword",
	}
	userResult, err := UserService.Login(userRequest)

	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "Username atau password tidak valid", err.Message())
}

func TestUserService_Login_UserNotFound(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		apiErr := rest_err.NewUnauthorizedError("Username atau password tidak valid")
		return nil, apiErr
	}

	userRequest := users.UserLoginRequest{
		Email:    "notExist@gmail.com",
		Password: "salahPassword",
	}
	userResult, err := UserService.Login(userRequest)

	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "Username atau password tidak valid", err.Message())
	assert.Equal(t, 401, err.Status())
}

func TestUserService_PutAvatar(t *testing.T) {
	putAvatarFunction = func(email string, avatar string) (*users.UserResponse, rest_err.APIError) {
		return &users.UserResponse{
			ID:        primitive.ObjectID{},
			Email:     "",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "images/whowhos@gmail.com.jpg",
			Timestamp: 0,
		}, nil
	}

	userResult, err := UserService.PutAvatar("whowhos@gmail.com", "images/whowhos@gmail.com.jpg")

	assert.Nil(t, err)
	assert.Equal(t, "images/whowhos@gmail.com.jpg", userResult.Avatar)
}

func TestUserService_PutAvatar_UserNotFound(t *testing.T) {
	putAvatarFunction = func(email string, avatar string) (*users.UserResponse, rest_err.APIError) {
		return nil, rest_err.NewBadRequestError(fmt.Sprintf("User avatar gagal diupload, user dengan email %s tidak ditemukan", email))
	}
	userResult, err := UserService.PutAvatar("whowhos@gmail.com", "images/whowhos@gmail.com.jpg")
	assert.Nil(t, userResult)
	assert.NotNil(t, err)
	assert.Equal(t, "User avatar gagal diupload, user dengan email whowhos@gmail.com tidak ditemukan", err.Message())
}

func TestUserService_ChangePassword_Success(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		return &users.User{
			ID:        primitive.ObjectID{},
			Email:     "whowho@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "",
			HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
			Timestamp: 0,
		}, nil
	}
	changePasswordFunction = func(data users.UserChangePasswordRequest) rest_err.APIError {
		return nil
	}

	data := users.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "Password",
		NewPassword: "NewPassword",
	}
	err := UserService.ChangePassword(data)

	assert.Nil(t, err)
}

func TestUserService_ChangePassword_FailPasswordSame(t *testing.T) {

	data := users.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "Password",
		NewPassword: "Password",
	}
	err := UserService.ChangePassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Gagal mengganti password, password tidak boleh sama dengan sebelumnya!", err.Message())
}

func TestUserService_ChangePassword_OldPasswordWrong(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		return &users.User{
			ID:        primitive.ObjectID{},
			Email:     "whowho@gmail.com",
			Name:      "Muchlis",
			IsAdmin:   false,
			Avatar:    "",
			HashPw:    "$2a$04$N.8j0ys/1t8YBZuM051PQOq3B6p5hFNv2hzYr.1vooL65z9Bmb7fO",
			Timestamp: 0,
		}, nil
	}

	data := users.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "salahPassword",
		NewPassword: "NewPassword",
	}
	err := UserService.ChangePassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Gagal mengganti password, password salah!", err.Message())
}

func TestUserService_ChangePassword_EmailWrong(t *testing.T) {
	getUserByEmailWithPasswordFunction = func(email string) (*users.User, rest_err.APIError) {
		apiErr := rest_err.NewUnauthorizedError("Username atau password tidak valid")
		return nil, apiErr
	}

	data := users.UserChangePasswordRequest{
		Email:       "email.salah@gmail.com",
		Password:    "password",
		NewPassword: "Password",
	}
	err := UserService.ChangePassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Username atau password tidak valid", err.Message())
}

func TestUserService_ResetPassword(t *testing.T) {
	changePasswordFunction = func(data users.UserChangePasswordRequest) rest_err.APIError {
		return nil
	}

	data := users.UserChangePasswordRequest{
		Email:       "whowho@gmail.com",
		Password:    "",
		NewPassword: "PasswordBaru",
	}
	err := UserService.ResetPassword(data)

	assert.Nil(t, err)
}

func TestUserService_ResetPassword_EmailNotFound(t *testing.T) {
	changePasswordFunction = func(data users.UserChangePasswordRequest) rest_err.APIError {
		return rest_err.NewBadRequestError("Penggantian password gagal, email salah")
	}

	data := users.UserChangePasswordRequest{
		Email:       "emailsalah@gmail.com",
		Password:    "",
		NewPassword: "PasswordBaru",
	}
	err := UserService.ResetPassword(data)

	assert.NotNil(t, err)
	assert.Equal(t, "Penggantian password gagal, email salah", err.Message())
}
