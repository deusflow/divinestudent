package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq" // postgres driver
	"golang.org/x/crypto/bcrypt"
)

// remove old refresh tokens
func cleanupExpiredRefreshTokens() {
	_, err := db.Exec("DELETE FROM refresh_tokens WHERE expires_at < now()")
	if err != nil {
		log.Println("Error clearing refresh tokens:", err)
	}
}

var (
	db        *sql.DB
	jwtSecret = []byte("your-secret-key") // change to real secret
)

// Claims for JWT
// holds user ID and expiry info
type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

// Student holds student data
type Student struct {
	ID                  int        `json:"id"`
	Name                string     `json:"name" binding:"required"`
	FieldOfStudy        string     `json:"field_of_study" binding:"required"`
	Email               string     `json:"email" binding:"required"`
	HasAssignment       *bool      `json:"has_assignment"`
	CitizenName         string     `json:"citizen_name"`
	ContactPhoneEmail   string     `json:"contact_phone_email"`
	Address             string     `json:"address"`
	AssignmentType      string     `json:"assignment_type"`
	AssignmentCompleted *bool      `json:"assignment_completed"`
	AgreementDate       *time.Time `json:"agreement_date,omitempty"`
	TimeSlot            string     `json:"time_slot"`
	Notes               string     `json:"notes"`
	Active              *bool      `json:"active"`
}

// MarshalJSON custom JSON output for stud to format agreementdata as YYYY-MM-DD
func (s *Student) MarshalJSON() ([]byte, error) {
	type Alias Student
	aux := struct {
		AgreementDate string `json:"agreement_date,omitempty"`
		Alias
	}{
		Alias: *(*Alias)(s),
	}
	if s.AgreementDate != nil {
		aux.AgreementDate = s.AgreementDate.Format("2006-01-02")
	}
	return json.Marshal(aux)
}

// UnmarshalJSON : custom JSON input for Student to parse AgreementDate from YYYY-MM-DD
func (s *Student) UnmarshalJSON(data []byte) error {
	type Alias Student
	aux := &struct {
		AgreementDate string `json:"agreement_date"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.AgreementDate != "" {
		t, err := time.Parse("2006-01-02", aux.AgreementDate)
		if err != nil {
			return err
		}
		s.AgreementDate = &t
	} else {
		s.AgreementDate = nil
	}
	return nil
}

func main() {
	// connect to db
	var err error
	db, err = sql.Open("postgres", "postgresql://neondb_owner:npg_QvU0aSNJOK1r@ep-white-breeze-a9bn0pc6-pooler.gwc.azure.neon.tech/neondb?sslmode=require&channel_binding=require")
	if err != nil {
		panic(err)
	}
	// check db
	if err = db.Ping(); err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(25)                 // Максимум 25 одновременных соединений с базой
	db.SetMaxIdleConns(25)                 // Максимум 25 соединений может простаивать без работы
	db.SetConnMaxLifetime(5 * time.Minute) // Каждое соединение живёт не больше 5 минут
	cleanupExpiredRefreshTokens()

	go func() {
		for {
			cleanupExpiredRefreshTokens()
			time.Sleep(24 * time.Hour) // чистить раз в сутки токены
		}
	}()

	r := gin.Default() // router
	// serve static
	r.Static("/static", "../frontend")

	// fallback for SPA
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == "/login" || (len(path) >= 4 && path[:4] == "/api") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}
		c.File("../frontend/index.html")
	})

	// public routes
	r.POST("/login", login)
	r.POST("/refresh", refresh)
	r.POST("/logout", logout)
	r.GET("/students", getStudents)

	// protected routes
	auth := r.Group("/")
	auth.Use(authMiddleware())
	{
		auth.GET("/students/:id", getStudentByID)
		auth.POST("/students", addStudent)
		auth.PUT("/students/:id", updateStudent)
		auth.DELETE("/students/:id", deleteStudent)
	}

	r.Run(":8080") // run server
}

// login: verify user and send tokens
func login(c *gin.Context) {
	var creds struct{ Username, Password string }
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
		return
	}

	var userID int
	var passwordHash string
	// get user
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = $1", creds.Username).
		Scan(&userID, &passwordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}
	// check pass
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(creds.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Wrong password"})
		return
	}

	// make JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:           userID,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))},
	})
	tokenString, _ := token.SignedString(jwtSecret)

	// make refresh token
	rtb := make([]byte, 32)
	if _, err := rand.Read(rtb); err != nil {
		log.Println("Ошибка генерации refresh-токена:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
		return
	}
	refreshToken := hex.EncodeToString(rtb)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if _, err := db.Exec("INSERT INTO refresh_tokens(token, user_id, expires_at) VALUES($1,$2,$3)", refreshToken, userID, expiresAt); err != nil {
		log.Println("Ошибка вставки refresh-токена:", err)
	}
	// send cookie + jwt
	c.SetCookie("refresh_token", refreshToken, int((7 * 24 * time.Hour).Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"jwt": tokenString})
}

// refresh: check refresh token and give new jwt
func refresh(c *gin.Context) {
	rt, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token"})
		return
	}

	var userID int
	var exp time.Time
	// lookup
	err = db.QueryRow("SELECT user_id, expires_at FROM refresh_tokens WHERE token = $1", rt).
		Scan(&userID, &exp)
	if err != nil || exp.Before(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bad refresh"})
		return
	}

	// new jwt
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute))},
	})
	tokStr, _ := token.SignedString(jwtSecret)
	c.JSON(http.StatusOK, gin.H{"jwt": tokStr})
}

// logout: remove refresh token
func logout(c *gin.Context) {
	rt, err := c.Cookie("refresh_token")
	if err == nil {
		if _, delErr := db.Exec("DELETE FROM refresh_tokens WHERE token = $1", rt); delErr != nil {
			log.Println("Error deleting refresh token:", delErr)
		}
	}
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// authMiddleware: protect routes
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if len(h) < 7 || h[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token"})
			c.Abort()
			return
		}
		t, err := jwt.ParseWithClaims(h[7:], &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !t.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bad token"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// getStudents: fetch all rows
func getStudents(c *gin.Context) {
	rows, err := db.Query("SELECT * FROM students") // later you can add a full select for each required field
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DB error"})
		return
	}
	defer rows.Close()

	var students []Student
	for rows.Next() {
		var s Student
		var (
			hasAssign sql.NullBool
			citizen   sql.NullString
			contact   sql.NullString
			addr      sql.NullString
			atype     sql.NullString
			acomp     sql.NullBool
			adate     sql.NullTime
			tslot     sql.NullString
			notes     sql.NullString
			active    sql.NullBool
		)
		err = rows.Scan(&s.ID, &s.Name, &s.FieldOfStudy, &s.Email, &hasAssign, &citizen,
			&contact, &addr, &atype, &acomp, &adate, &tslot, &notes, &active)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan error"})
			return
		}
		// map nulls
		if hasAssign.Valid {
			s.HasAssignment = &hasAssign.Bool
		}
		if acomp.Valid {
			s.AssignmentCompleted = &acomp.Bool
		}
		if active.Valid {
			s.Active = &active.Bool
		}
		s.CitizenName = citizen.String
		s.ContactPhoneEmail = contact.String
		s.Address = addr.String
		s.AssignmentType = atype.String
		if adate.Valid {
			s.AgreementDate = &adate.Time
		} else {
			s.AgreementDate = nil
		}
		s.TimeSlot = tslot.String
		s.Notes = notes.String
		students = append(students, s)
	}
	c.JSON(http.StatusOK, students)
}

// getStudentByID: fetch single
func getStudentByID(c *gin.Context) {
	id := c.Param("id")
	var s Student
	var (
		hasAssign sql.NullBool
		citizen   sql.NullString
		contact   sql.NullString
		addr      sql.NullString
		atype     sql.NullString
		acomp     sql.NullBool
		adate     sql.NullTime
		tslot     sql.NullString
		notes     sql.NullString
		active    sql.NullBool
	)
	err := db.QueryRow("SELECT * FROM students WHERE id=$1", id).Scan(
		&s.ID, &s.Name, &s.FieldOfStudy, &s.Email, &hasAssign, &citizen,
		&contact, &addr, &atype, &acomp, &adate, &tslot, &notes, &active)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	// map nulls
	if hasAssign.Valid {
		s.HasAssignment = &hasAssign.Bool
	}
	if acomp.Valid {
		s.AssignmentCompleted = &acomp.Bool
	}
	if active.Valid {
		s.Active = &active.Bool
	}
	s.CitizenName = citizen.String
	s.ContactPhoneEmail = contact.String
	s.Address = addr.String
	s.AssignmentType = atype.String
	if adate.Valid {
		s.AgreementDate = &adate.Time
	} else {
		s.AgreementDate = nil
	}
	s.TimeSlot = tslot.String
	s.Notes = notes.String
	c.JSON(http.StatusOK, s)
}

// addStudent: insert new
func addStudent(c *gin.Context) {
	var s Student
	if err := c.BindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad data"})
		return
	}
	if s.Name == "" || s.FieldOfStudy == "" || s.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name, field_of_study, and email are required"})
		return
	}
	if !isValidEmail(s.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// handle date
	var ad interface{}
	if s.AgreementDate == nil {
		ad = nil
	} else {
		ad = *s.AgreementDate
	}
	_, err := db.Exec(`INSERT INTO students (name, field_of_study, email, has_assignment, citizen_name,
		contact_phone_email, address, assignment_type, assignment_completed, agreement_date, time_slot, notes, active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.Name, s.FieldOfStudy, s.Email, s.HasAssignment, s.CitizenName, s.ContactPhoneEmail, s.Address,
		s.AssignmentType, s.AssignmentCompleted, ad, s.TimeSlot, s.Notes, s.Active)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Insert fail"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Added"})
}

// updateStudent: update existing
func updateStudent(c *gin.Context) {
	id := c.Param("id")
	var s Student
	if err := c.BindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad data"})
		return
	}
	if s.Name == "" || s.FieldOfStudy == "" || s.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name, field_of_study, and email are required"})
		return
	}
	if !isValidEmail(s.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// handle date
	var ad interface{}
	if s.AgreementDate == nil {
		ad = nil
	} else {
		ad = *s.AgreementDate
	}
	_, err := db.Exec(`UPDATE students SET name=$1, field_of_study=$2, email=$3, has_assignment=$4,
		citizen_name=$5, contact_phone_email=$6, address=$7, assignment_type=$8, assignment_completed=$9,
		agreement_date=$10, time_slot=$11, notes=$12, active=$13 WHERE id=$14`,
		s.Name, s.FieldOfStudy, s.Email, s.HasAssignment, s.CitizenName, s.ContactPhoneEmail, s.Address,
		s.AssignmentType, s.AssignmentCompleted, ad, s.TimeSlot, s.Notes, s.Active, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update fail"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Updated"})
}

// deleteStudent: delete record
func deleteStudent(c *gin.Context) {
	id := c.Param("id")
	_, err := db.Exec("DELETE FROM students WHERE id=$1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Delete fail"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[\w.-]+@[\w.-]+\.\w+$`)
	return re.MatchString(email)
}
