package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret = []byte("your-secret-key") // Замените на безопасный ключ
)

// Claims для JWT-токена
type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

// Структура Student
type Student struct {
	ID                  int    `json:"id"`
	Name                string `json:"name" binding:"required"`
	FieldOfStudy        string `json:"field_of_study" binding:"required"`
	Email               string `json:"email" binding:"required"`
	HasAssignment       *bool  `json:"has_assignment"`
	CitizenName         string `json:"citizen_name"`
	ContactPhoneEmail   string `json:"contact_phone_email"`
	Address             string `json:"address"`
	AssignmentType      string `json:"assignment_type"`
	AssignmentCompleted *bool  `json:"assignment_completed"`
	AgreementDate       string `json:"agreement_date"`
	TimeSlot            string `json:"time_slot"`
	Notes               string `json:"notes"`
	Active              *bool  `json:"active"`
}

func main() {
	var err error
	// Подключение к базе данных (обновлено на ваш connection string)
	db, err = sql.Open("postgres", "postgresql://neondb_owner:npg_QvU0aSNJOK1r@ep-white-breeze-a9bn0pc6-pooler.gwc.azure.neon.tech/neondb?sslmode=require&channel_binding=require")
	if err != nil {
		panic(err)
	}
	// Проверка соединения
	if err = db.Ping(); err != nil {
		panic(err)
	}

	r := gin.Default()

	// Обслуживание статических файлов
	r.Static("/static", "../frontend")

	// Отдавать index.html для всех не-API маршрутов (SPA)
	r.NoRoute(func(c *gin.Context) {
		// Если путь начинается с /api или /login, возвращаем 404
		if c.Request.URL.Path == "/login" || len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}
		c.File("../frontend/index.html")
	})

	// Публичные маршруты
	r.POST("/login", login)
	r.POST("/refresh", refresh)
	r.POST("/logout", logout)
	r.GET("/students", getStudents)

	// Защищенные маршруты
	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/students/:id", getStudentByID)
		protected.POST("/students", addStudent)
		protected.PUT("/students/:id", updateStudent)
		protected.DELETE("/students/:id", deleteStudent)
	}

	r.Run(":8080")
}

// Функция логина
func login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный запрос"})
		return
	}

	var userID int
	var passwordHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = $1", creds.Username).
		Scan(&userID, &passwordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found", "debug": err.Error()})
		return
	}
	// Проверяем пароль для любого пользователя
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(creds.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "password mismatch", "debug": passwordHash, "input": creds.Password})
		return
	}

	// Генерация JWT-токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	})
	tokenString, _ := token.SignedString(jwtSecret)

	// Генерация refresh-токена
	refreshTokenBytes := make([]byte, 32)
	rand.Read(refreshTokenBytes)
	refreshToken := hex.EncodeToString(refreshTokenBytes)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	_, err = db.Exec("INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)",
		refreshToken, userID, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить refresh-токен"})
		return
	}

	// Установка refresh-токена в cookie
	c.SetCookie("refresh_token", refreshToken, int((7 * 24 * time.Hour).Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"jwt": tokenString})
}

// Функция обновления токена
func refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh-токен отсутствует"})
		return
	}

	var userID int
	var expiresAt time.Time
	err = db.QueryRow("SELECT user_id, expires_at FROM refresh_tokens WHERE token = $1", refreshToken).
		Scan(&userID, &expiresAt)
	if err != nil || expiresAt.Before(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный или просроченный refresh-токен"})
		return
	}

	// Генерация нового JWT-токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	})
	tokenString, _ := token.SignedString(jwtSecret)

	c.JSON(http.StatusOK, gin.H{"jwt": tokenString})
}

// Функция выхода
func logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		db.Exec("DELETE FROM refresh_tokens WHERE token = $1", refreshToken)
	}
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Выход выполнен"})
}

// Middleware для проверки аутентификации
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует или неверный токен"})
			c.Abort()
			return
		}

		tokenString := authHeader[7:]
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Получение списка студентов
func getStudents(c *gin.Context) {
	rows, err := db.Query("SELECT * FROM students")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	defer rows.Close()

	var students []Student
	for rows.Next() {
		var s Student
		var (
			hasAssignment       sql.NullBool
			citizenName         sql.NullString
			contactPhoneEmail   sql.NullString
			address             sql.NullString
			assignmentType      sql.NullString
			assignmentCompleted sql.NullBool
			agreementDate       sql.NullTime
			timeSlot            sql.NullString
			notes               sql.NullString
			active              sql.NullBool
		)
		err := rows.Scan(&s.ID, &s.Name, &s.FieldOfStudy, &s.Email, &hasAssignment, &citizenName,
			&contactPhoneEmail, &address, &assignmentType, &assignmentCompleted, &agreementDate,
			&timeSlot, &notes, &active)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сканирования", "debug": err.Error()})
			return
		}
		if hasAssignment.Valid {
			s.HasAssignment = &hasAssignment.Bool
		} else {
			s.HasAssignment = nil
		}
		if assignmentCompleted.Valid {
			s.AssignmentCompleted = &assignmentCompleted.Bool
		} else {
			s.AssignmentCompleted = nil
		}
		if active.Valid {
			s.Active = &active.Bool
		} else {
			s.Active = nil
		}
		s.CitizenName = citizenName.String
		s.ContactPhoneEmail = contactPhoneEmail.String
		s.Address = address.String
		s.AssignmentType = assignmentType.String
		if agreementDate.Valid {
			s.AgreementDate = agreementDate.Time.Format("2006-01-02")
		} else {
			s.AgreementDate = ""
		}
		s.TimeSlot = timeSlot.String
		s.Notes = notes.String
		students = append(students, s)
	}
	c.JSON(http.StatusOK, students)
}

// Получение одного студента по id
func getStudentByID(c *gin.Context) {
	id := c.Param("id")
	var s Student
	var (
		hasAssignment       sql.NullBool
		citizenName         sql.NullString
		contactPhoneEmail   sql.NullString
		address             sql.NullString
		assignmentType      sql.NullString
		assignmentCompleted sql.NullBool
		agreementDate       sql.NullTime
		timeSlot            sql.NullString
		notes               sql.NullString
		active              sql.NullBool
	)
	err := db.QueryRow("SELECT * FROM students WHERE id = $1", id).Scan(
		&s.ID, &s.Name, &s.FieldOfStudy, &s.Email, &hasAssignment, &citizenName,
		&contactPhoneEmail, &address, &assignmentType, &assignmentCompleted, &agreementDate,
		&timeSlot, &notes, &active)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Student not found", "debug": err.Error()})
		return
	}
	if hasAssignment.Valid {
		s.HasAssignment = &hasAssignment.Bool
	} else {
		s.HasAssignment = nil
	}
	if assignmentCompleted.Valid {
		s.AssignmentCompleted = &assignmentCompleted.Bool
	} else {
		s.AssignmentCompleted = nil
	}
	if active.Valid {
		s.Active = &active.Bool
	} else {
		s.Active = nil
	}
	s.CitizenName = citizenName.String
	s.ContactPhoneEmail = contactPhoneEmail.String
	s.Address = address.String
	s.AssignmentType = assignmentType.String
	if agreementDate.Valid {
		s.AgreementDate = agreementDate.Time.Format("2006-01-02")
	} else {
		s.AgreementDate = ""
	}
	s.TimeSlot = timeSlot.String
	s.Notes = notes.String
	c.JSON(http.StatusOK, s)
}

// Добавление студента
func addStudent(c *gin.Context) {
	var s Student
	if err := c.BindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	agreementDate := interface{}(s.AgreementDate)
	if s.AgreementDate == "" {
		agreementDate = nil
	}
	_, err := db.Exec(`INSERT INTO students (name, field_of_study, email, has_assignment, citizen_name, 
		contact_phone_email, address, assignment_type, assignment_completed, agreement_date, time_slot, notes, active) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		s.Name, s.FieldOfStudy, s.Email, s.HasAssignment, s.CitizenName, s.ContactPhoneEmail, s.Address,
		s.AssignmentType, s.AssignmentCompleted, agreementDate, s.TimeSlot, s.Notes, s.Active)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось добавить студента", "debug": err.Error(), "student": s})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Студент добавлен"})
}

// Обновление студента (уже есть в вашем коде)
func updateStudent(c *gin.Context) {
	id := c.Param("id")
	var s Student
	if err := c.BindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	agreementDate := interface{}(s.AgreementDate)
	if s.AgreementDate == "" {
		agreementDate = nil
	}

	_, err := db.Exec(`UPDATE students SET name=$1, field_of_study=$2, email=$3, has_assignment=$4, 
		citizen_name=$5, contact_phone_email=$6, address=$7, assignment_type=$8, assignment_completed=$9, 
		agreement_date=$10, time_slot=$11, notes=$12, active=$13 WHERE id=$14`,
		s.Name, s.FieldOfStudy, s.Email, s.HasAssignment, s.CitizenName, s.ContactPhoneEmail, s.Address,
		s.AssignmentType, s.AssignmentCompleted, agreementDate, s.TimeSlot, s.Notes, s.Active, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить студента", "debug": err.Error(), "student": s})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Студент обновлен"})
}

// Удаление студента
func deleteStudent(c *gin.Context) {
	id := c.Param("id")
	_, err := db.Exec("DELETE FROM students WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить студента"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Студент удален"})
}
