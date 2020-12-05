package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/muchlist/auth_service_go/utils/mjwt"
	"github.com/muchlist/erru_utils_go/rest_err"
	"strings"
)

const (
	headerKey = "Authorization"
	bearerKey = "Bearer"
)

type role int

const (
	normalAuth role = iota
	adminAuth
)

//AuthMiddleware memvalidasi token JWT, mengembalikan claims berupa pointer mjwt.CustomClaims
func AuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get(headerKey)
	claims, err := authValidator(authHeader, normalAuth)
	if err != nil {
		return c.Status(err.Status()).JSON(err)
	}

	c.Locals(mjwt.CLAIMS, claims)
	return c.Next()
}

//AuthAdminMiddleware memvalidasi token JWT, mengembalikan claims berupa pointer mjwt.CustomClaims.
//perbedaannya dengan AuthMidlleware adalah ini mengharuskan pengakses berstatus is_admin true
func AuthAdminMiddleware(c *fiber.Ctx) error {

	authHeader := c.Get(headerKey)
	claims, err := authValidator(authHeader, adminAuth)
	if err != nil {
		return c.Status(err.Status()).JSON(err)
	}

	c.Locals(mjwt.CLAIMS, claims)
	return c.Next()
}

func authValidator(authHeader string, role role) (*mjwt.CustomClaim, rest_err.APIError) {
	if !strings.Contains(authHeader, bearerKey) {
		apiErr := rest_err.NewUnauthorizedError("Unauthorized")
		return nil, apiErr
	}

	tokenString := strings.Split(authHeader, " ")
	if len(tokenString) != 2 {
		apiErr := rest_err.NewUnauthorizedError("Unauthorized")
		return nil, apiErr
	}

	token, err := mjwt.Obj.ValidateToken(tokenString[1])
	if err != nil {
		return nil, err
	}

	claims, err := mjwt.Obj.ReadToken(token)
	if err != nil {
		return nil, err
	}

	if role == adminAuth {
		if !claims.IsAdmin {
			apiErr := rest_err.NewUnauthorizedError("Unauthorized, memerlukan hak akses admin")
			return nil, apiErr
		}
	}

	return claims, nil
}
