package services

import (
	"github.com/muchlist/auth_service_go/domains/users"
	"github.com/muchlist/auth_service_go/utils/crypt"
	"github.com/muchlist/auth_service_go/utils/mjwt"
	"github.com/muchlist/erru_utils_go/rest_err"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"strings"
	"time"
)

var (
	// UserService variabel publik
	UserService userServiceInterface = &userService{}
)

type userService struct{}

type userServiceInterface interface {
	GetUser(primitive.ObjectID) (*users.UserResponse, rest_err.APIError)
	GetUserByEmail(email string) (*users.UserResponse, rest_err.APIError)
	InsertUser(users.UserRequest) (*string, rest_err.APIError)
	FindUsers() (users.UserResponseList, rest_err.APIError)
	EditUser(email string, userEdit users.UserEditRequest) (*users.UserResponse, rest_err.APIError)
	DeleteUser(email string) rest_err.APIError
	Login(users.UserLoginRequest) (*users.UserLoginResponse, rest_err.APIError)
	PutAvatar(email string, fileLocation string) (*users.UserResponse, rest_err.APIError)
	ChangePassword(data users.UserChangePasswordRequest) rest_err.APIError
	ResetPassword(data users.UserChangePasswordRequest) rest_err.APIError
}

//GetUser mendapatkan user dari domain
func (u *userService) GetUser(userID primitive.ObjectID) (*users.UserResponse, rest_err.APIError) {
	user, err := users.UserDao.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

//GetUserByEmail mendapatkan user berdasarkan email
func (u *userService) GetUserByEmail(email string) (*users.UserResponse, rest_err.APIError) {
	user, err := users.UserDao.GetUserByEmail(strings.ToLower(email))
	if err != nil {
		return nil, err
	}
	return user, nil
}

//FindUsers
func (u *userService) FindUsers() (users.UserResponseList, rest_err.APIError) {
	userList, err := users.UserDao.FindUser()
	if err != nil {
		return nil, err
	}
	return userList, nil
}

//InsertUser melakukan register user semua email yang di registrasikan diubah menjadi lowercase di tahap ini
func (u *userService) InsertUser(user users.UserRequest) (*string, rest_err.APIError) {

	user.Email = strings.ToLower(user.Email)

	// cek ketersediaan email
	_, err := users.UserDao.CheckEmailAvailable(user.Email)
	if err != nil {
		return nil, err
	}
	// END cek ketersediaan email

	hashPassword, err := crypt.Obj.GenerateHash(user.Password)
	if err != nil {
		return nil, err
	}

	user.Password = hashPassword
	user.Timestamp = time.Now().Unix()

	insertedID, err := users.UserDao.InsertUser(user)
	if err != nil {
		return nil, err
	}
	return insertedID, nil
}

//EditUser
func (u *userService) EditUser(email string, request users.UserEditRequest) (*users.UserResponse, rest_err.APIError) {
	result, err := users.UserDao.EditUser(strings.ToLower(email), request)
	if err != nil {
		return nil, err
	}
	return result, nil
}

//DeleteUser
func (u *userService) DeleteUser(email string) rest_err.APIError {
	err := users.UserDao.DeleteUser(email)
	if err != nil {
		return err
	}

	return nil
}

//Login
func (u *userService) Login(login users.UserLoginRequest) (*users.UserLoginResponse, rest_err.APIError) {

	login.Email = strings.ToLower(login.Email)

	user, err := users.UserDao.GetUserByEmailWithPassword(login.Email)
	if err != nil {
		return nil, err
	}

	if !crypt.Obj.IsPWAndHashPWMatch(login.Password, user.HashPw) {
		return nil, rest_err.NewUnauthorizedError("Username atau password tidak valid")
	}

	claims := mjwt.CustomClaim{
		Identity:  user.Email,
		Name:      user.Name,
		IsAdmin:   user.IsAdmin,
		TimeExtra: 30 * 24, //30 hari * 24 Jam
		Jti:       "",
	}

	token, err := mjwt.Obj.GenerateToken(claims)
	if err != nil {
		return nil, err
	}

	userResponse := users.UserLoginResponse{
		Name:        user.Name,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		Avatar:      user.Avatar,
		AccessToken: token,
	}

	return &userResponse, nil

}

//PutAvatar memasukkan lokasi file (path) ke dalam database user
func (u *userService) PutAvatar(email string, fileLocation string) (*users.UserResponse, rest_err.APIError) {

	email = strings.ToLower(email)

	user, err := users.UserDao.PutAvatar(email, fileLocation)
	if err != nil {
		return nil, err
	}

	return user, nil
}

//ChangePassword melakukan perbandingan hashpassword lama dan memasukkan hashpassword baru ke database
func (u *userService) ChangePassword(data users.UserChangePasswordRequest) rest_err.APIError {

	if data.Password == data.NewPassword {
		return rest_err.NewBadRequestError("Gagal mengganti password, password tidak boleh sama dengan sebelumnya!")
	}

	userResult, err := users.UserDao.GetUserByEmailWithPassword(data.Email)
	if err != nil {
		return err
	}

	if !crypt.Obj.IsPWAndHashPWMatch(data.Password, userResult.HashPw) {
		return rest_err.NewBadRequestError("Gagal mengganti password, password salah!")
	}

	newPasswordHash, err := crypt.Obj.GenerateHash(data.NewPassword)
	if err != nil {
		return err
	}
	data.NewPassword = newPasswordHash

	_ = users.UserDao.ChangePassword(data)

	return nil
}

//ResetPassword . inputan password berada di level controller
//hanya memproses field newPassword, mengabaikan field password
func (u *userService) ResetPassword(data users.UserChangePasswordRequest) rest_err.APIError {

	data.Email = strings.ToLower(data.Email)

	newPasswordHash, err := crypt.Obj.GenerateHash(data.NewPassword)
	if err != nil {
		return err
	}
	data.NewPassword = newPasswordHash

	err = users.UserDao.ChangePassword(data)
	if err != nil {
		return err
	}

	return nil
}
