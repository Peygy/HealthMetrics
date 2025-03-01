package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User представляет собой модель пользователя
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	Email     string    `gorm:"unique" json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// HealthData представляет собой модель данных о здоровье
type HealthData struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	UserID          uint      `json:"user_id"`
	HeartRate       int       `json:"heart_rate"`       // Пульс
	BloodPressure   string    `json:"blood_pressure"`   // Артериальное давление
	BloodSugar      float64   `json:"blood_sugar"`      // Уровень сахара в крови
	Weight          float64   `json:"weight"`           // Вес
	OxygenLevel     float64   `json:"oxygen_level"`     // Уровень кислорода в крови (SpO2)
	BodyTemperature float64   `json:"body_temperature"` // Температура тела
	StressLevel     int       `json:"stress_level"`     // Уровень стресса (0-100)
	Steps           int       `json:"steps"`            // Количество шагов
	CaloriesBurned  float64   `json:"calories_burned"`  // Сожженные калории
	Timestamp       time.Time `json:"timestamp"`        // Временная метка
}

// HealthReport представляет собой модель отчета о здоровье
type HealthReport struct {
	ID                     uint      `gorm:"primaryKey" json:"id"`
	UserID                 uint      `json:"user_id"`
	AverageHeartRate       float64   `json:"average_heart_rate"`
	AverageBloodSugar      float64   `json:"average_blood_sugar"`
	AverageWeight          float64   `json:"average_weight"`
	AverageOxygenLevel     float64   `json:"average_oxygen_level"`
	AverageBodyTemperature float64   `json:"average_body_temperature"`
	AverageStressLevel     int       `json:"average_stress_level"`
	AverageSteps           int       `json:"average_steps"`
	AverageCaloriesBurned  float64   `json:"average_calories_burned"`
	Timestamp              time.Time `json:"timestamp"`
}

var db *gorm.DB
var jwtKey = []byte("my_secret_key")

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("health_monitor.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database")
	}

	// Автомиграция таблиц
	db.AutoMigrate(&User{}, &HealthData{}, &HealthReport{})
}

func main() {
	initDB()

	r := mux.NewRouter()

	// Маршруты для авторизации
	r.HandleFunc("/register", register).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")

	// Маршруты для пользователей
	r.HandleFunc("/users/{id}", getUser).Methods("GET")

	// Маршруты для данных о здоровье
	r.HandleFunc("/health", authMiddleware(addHealthData)).Methods("POST")
	r.HandleFunc("/health/{userID}", authMiddleware(getHealthData)).Methods("GET")
	r.HandleFunc("/health/report/{userID}", authMiddleware(generateHealthReport)).Methods("GET")
	r.HandleFunc("/health/reports/{userID}", authMiddleware(getAllReports)).Methods("GET")

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// Регистрация нового пользователя
func register(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	// Хеширование пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)
	user.CreatedAt = time.Now()

	db.Create(&user)
	json.NewEncoder(w).Encode(user)
}

// Логин пользователя
func login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&credentials)

	var user User
	db.Where("email = ?", credentials.Email).First(&user)

	if user.ID == 0 || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Генерация JWT токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, _ := token.SignedString(jwtKey)

	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

// Middleware для проверки авторизации
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// getUser возвращает информацию о пользователе по ID
func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var user User
	db.First(&user, params["id"])
	json.NewEncoder(w).Encode(user)
}

// addHealthData добавляет данные о здоровье для пользователя
func addHealthData(w http.ResponseWriter, r *http.Request) {
	var healthData HealthData
	json.NewDecoder(r.Body).Decode(&healthData)
	healthData.Timestamp = time.Now()
	db.Create(&healthData)
	json.NewEncoder(w).Encode(healthData)
}

// getHealthData возвращает данные о здоровье для пользователя
func getHealthData(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID, _ := strconv.Atoi(params["userID"])
	var healthData []HealthData
	db.Where("user_id = ?", userID).Find(&healthData)
	json.NewEncoder(w).Encode(healthData)
}

// generateHealthReport генерирует отчет о здоровье пользователя
func generateHealthReport(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID, _ := strconv.Atoi(params["userID"])

	// Получаем данные за последние 7 дней
	var healthData []HealthData
	db.Where("user_id = ? AND timestamp >= ?", userID, time.Now().AddDate(0, 0, -7)).Find(&healthData)

	// Анализ данных
	var totalHeartRate int
	var totalBloodSugar float64
	var totalWeight float64
	var totalOxygenLevel float64
	var totalBodyTemperature float64
	var totalStressLevel int
	var totalSteps int
	var totalCaloriesBurned float64
	count := len(healthData)

	for _, data := range healthData {
		totalHeartRate += data.HeartRate
		totalBloodSugar += data.BloodSugar
		totalWeight += data.Weight
		totalOxygenLevel += data.OxygenLevel
		totalBodyTemperature += data.BodyTemperature
		totalStressLevel += data.StressLevel
		totalSteps += data.Steps
		totalCaloriesBurned += data.CaloriesBurned
	}

	averageHeartRate := float64(totalHeartRate) / float64(count)
	averageBloodSugar := totalBloodSugar / float64(count)
	averageWeight := totalWeight / float64(count)
	averageOxygenLevel := totalOxygenLevel / float64(count)
	averageBodyTemperature := totalBodyTemperature / float64(count)
	averageStressLevel := totalStressLevel / count
	averageSteps := totalSteps / count
	averageCaloriesBurned := totalCaloriesBurned / float64(count)

	// Получаем предыдущий отчет
	var previousReport HealthReport
	db.Where("user_id = ?", userID).Order("timestamp desc").First(&previousReport)

	// Генерация рекомендаций с учетом разницы
	recommendations := generateRecommendations(
		averageHeartRate,
		averageBloodSugar,
		averageWeight,
		averageOxygenLevel,
		averageBodyTemperature,
		averageStressLevel,
		averageSteps,
		averageCaloriesBurned,
		previousReport,
	)

	// Сохраняем текущий отчет
	currentReport := HealthReport{
		UserID:                 uint(userID),
		AverageHeartRate:       averageHeartRate,
		AverageBloodSugar:      averageBloodSugar,
		AverageWeight:          averageWeight,
		AverageOxygenLevel:     averageOxygenLevel,
		AverageBodyTemperature: averageBodyTemperature,
		AverageStressLevel:     averageStressLevel,
		AverageSteps:           averageSteps,
		AverageCaloriesBurned:  averageCaloriesBurned,
		Timestamp:              time.Now(),
	}
	db.Create(&currentReport)

	// Формирование отчета
	report := map[string]interface{}{
		"current_report_date":      currentReport.Timestamp.Format("2006-01-02 15:04:05"),
		"previous_report_date":     previousReport.Timestamp.Format("2006-01-02 15:04:05"),
		"average_heart_rate":       averageHeartRate,
		"average_blood_sugar":      averageBloodSugar,
		"average_weight":           averageWeight,
		"average_oxygen_level":     averageOxygenLevel,
		"average_body_temperature": averageBodyTemperature,
		"average_stress_level":     averageStressLevel,
		"average_steps":            averageSteps,
		"average_calories_burned":  averageCaloriesBurned,
		"recommendations":          recommendations,
	}

	json.NewEncoder(w).Encode(report)
}

// getAllReports возвращает все отчеты для пользователя
func getAllReports(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID, _ := strconv.Atoi(params["userID"])
	var reports []HealthReport
	db.Where("user_id = ?", userID).Order("timestamp desc").Find(&reports)
	json.NewEncoder(w).Encode(reports)
}

// generateRecommendations генерирует рекомендации на основе данных
func generateRecommendations(
	heartRate, bloodSugar, weight, oxygenLevel, bodyTemperature float64,
	stressLevel, steps int,
	caloriesBurned float64,
	previousReport HealthReport,
) []string {
	var recommendations []string

	// Рекомендации по пульсу
	heartRateDiff := heartRate - previousReport.AverageHeartRate
	if heartRate > 80 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Ваш средний пульс выше нормы. По сравнению с предыдущим отчетом он изменился на %.1f. Рекомендуется снизить физическую нагрузку и проконсультироваться с врачом.",
			heartRateDiff,
		))
	} else {
		recommendations = append(recommendations, "Ваш средний пульс в норме.")
	}

	// Рекомендации по уровню сахара в крови
	bloodSugarDiff := bloodSugar - previousReport.AverageBloodSugar
	if bloodSugar > 6.0 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Уровень сахара в крови выше нормы. По сравнению с предыдущим отчетом он изменился на %.1f. Рекомендуется снизить потребление сахара и проконсультироваться с врачом.",
			bloodSugarDiff,
		))
	} else {
		recommendations = append(recommendations, "Уровень сахара в крови в норме.")
	}

	// Рекомендации по весу
	weightDiff := weight - previousReport.AverageWeight
	if weight > 90 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Ваш вес выше нормы. По сравнению с предыдущим отчетом он изменился на %.1f. Рекомендуется увеличить физическую активность и следить за питанием.",
			weightDiff,
		))
	} else {
		recommendations = append(recommendations, "Ваш вес в норме.")
	}

	// Рекомендации по уровню кислорода в крови
	oxygenLevelDiff := oxygenLevel - previousReport.AverageOxygenLevel
	if oxygenLevel < 95 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Уровень кислорода в крови ниже нормы. По сравнению с предыдущим отчетом он изменился на %.1f. Рекомендуется проверить дыхательную систему и проконсультироваться с врачом.",
			oxygenLevelDiff,
		))
	} else {
		recommendations = append(recommendations, "Уровень кислорода в крови в норме.")
	}

	// Рекомендации по температуре тела
	bodyTemperatureDiff := bodyTemperature - previousReport.AverageBodyTemperature
	if bodyTemperature > 37.5 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Температура тела выше нормы. По сравнению с предыдущим отчетом она изменилась на %.1f. Возможно, у вас жар. Рекомендуется отдохнуть и проконсультироваться с врачом.",
			bodyTemperatureDiff,
		))
	} else {
		recommendations = append(recommendations, "Температура тела в норме.")
	}

	// Рекомендации по уровню стресса
	stressLevelDiff := stressLevel - previousReport.AverageStressLevel
	if stressLevel > 50 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Уровень стресса выше нормы. По сравнению с предыдущим отчетом он изменился на %d. Рекомендуется расслабиться, заняться медитацией или йогой.",
			stressLevelDiff,
		))
	} else {
		recommendations = append(recommendations, "Уровень стресса в норме.")
	}

	// Рекомендации по количеству шагов
	stepsDiff := steps - previousReport.AverageSteps
	if steps < 5000 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Вы проходите меньше 5000 шагов в день. По сравнению с предыдущим отчетом количество шагов изменилось на %d. Рекомендуется увеличить физическую активность.",
			stepsDiff,
		))
	} else {
		recommendations = append(recommendations, "Вы проходите достаточно шагов в день. Продолжайте в том же духе!")
	}

	// Рекомендации по сожженным калориям
	caloriesBurnedDiff := caloriesBurned - previousReport.AverageCaloriesBurned
	if caloriesBurned < 2000 {
		recommendations = append(recommendations, fmt.Sprintf(
			"Вы сжигаете недостаточно калорий. По сравнению с предыдущим отчетом количество сожженных калорий изменилось на %.1f. Рекомендуется увеличить физическую активность.",
			caloriesBurnedDiff,
		))
	} else {
		recommendations = append(recommendations, "Вы сжигаете достаточно калорий. Отличная работа!")
	}

	return recommendations
}
