package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// --- Data Structures ---

type AttendanceResponse struct {
	StudentID         string   `json:"student_id"`
	TotalPresent      int      `json:"total_present"`
	TotalClasses      int      `json:"total_classes"`
	OverallPercentage float64  `json:"overall_percentage"`
	TodaysAttendance  []string `json:"todays_attendance"`
	SubjectAttendance []string `json:"subject_attendance"`
	SkippableHours    int      `json:"skippable_hours"`
	RequiredHours     int      `json:"required_hours"`
	Error             string   `json:"error,omitempty"`
}

type TimeSlot struct {
	Period    string `json:"period"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

type PeriodDetail struct {
	TimeSlot TimeSlot `json:"time_slot"`
	Subject  string   `json:"subject"`
	Faculty  string   `json:"faculty"`
}

type DaySchedule struct {
	Day     string         `json:"day"`
	Periods []PeriodDetail `json:"periods"`
}

type Subject struct {
	Code    string `json:"code"`
	Name    string `json:"name"`
	Faculty string `json:"faculty"`
}

type TimetableResponse struct {
	StudentID string        `json:"student_id"`
	Schedule  []DaySchedule `json:"schedule"`
	Subjects  []Subject     `json:"subjects"`
	Error     string        `json:"error,omitempty"`
}

// AJAX Response structure
type AjaxResponse struct {
	Request interface{} `json:"request"`
	Error   interface{} `json:"error"`
	Value   string      `json:"value"`
}

// --- Helper Functions ---

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func encryptPasswordAES(plainText string) (string, error) {
	key := []byte("8701661282118308")
	iv := []byte("8701661282118308")
	plaintextBytes := pkcs7Pad([]byte(plainText), aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, len(plaintextBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plaintextBytes)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func extractHiddenFields(body []byte) (string, string, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}

	viewState, exists1 := doc.Find("input[name='__VIEWSTATE']").Attr("value")
	eventValidation, exists2 := doc.Find("input[name='__EVENTVALIDATION']").Attr("value")

	if !exists1 || !exists2 {
		return "", "", fmt.Errorf("missing viewstate or eventvalidation")
	}

	return viewState, eventValidation, nil
}

// Original attendance calculation functions from your working code
func calculateSkippableHours(present, total int) int {
	if total == 0 || float64(present)/float64(total)*100 < 75 {
		return 0
	}
	skippable := 0
	tempPresent := present
	tempTotal := total
	for {
		tempTotal++
		if float64(tempPresent)/float64(tempTotal)*100 >= 75 {
			skippable++
		} else {
			break
		}
	}
	return skippable
}

func calculateRequiredHours(present, total int) int {
	if total == 0 || float64(present)/float64(total)*100 >= 75 {
		return 0
	}
	required := 0
	tempPresent := present
	tempTotal := total
	for {
		tempPresent++
		tempTotal++
		required++
		if float64(tempPresent)/float64(tempTotal)*100 >= 75 {
			break
		}
	}
	return required
}

func getCurrentDate() string {
	now := time.Now()
	return fmt.Sprintf("%02d/%02d", now.Day(), int(now.Month()))
}

func parseAttendanceValue(text string) (int, int) {
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.TrimSpace(text)

	re := regexp.MustCompile(`(\d+)\s*/\s*(\d+)`)
	matches := re.FindStringSubmatch(text)

	if len(matches) >= 3 {
		present, _ := strconv.Atoi(matches[1])
		total, _ := strconv.Atoi(matches[2])
		return present, total
	}

	return 0, 0
}

func parseTimeSlot(headerText string) TimeSlot {
	// Clean the header text and extract period info
	headerText = strings.ReplaceAll(headerText, "<br/>", "\n")
	headerText = strings.ReplaceAll(headerText, "<br>", "\n")

	lines := strings.Split(headerText, "\n")
	if len(lines) < 3 {
		return TimeSlot{}
	}

	period := strings.TrimSpace(lines[0])
	startTime := strings.TrimSpace(lines[1])
	endTime := strings.TrimSpace(lines[2])

	return TimeSlot{
		Period:    period,
		StartTime: startTime,
		EndTime:   endTime,
	}
}

func findFacultyForSubject(subjectCode string, subjects []Subject) string {
	for _, subject := range subjects {
		if subject.Code == subjectCode {
			return subject.Faculty
		}
	}
	return "Unknown Faculty"
}

// --- Core Logic ---

func authenticateUser(username, password string) (*http.Client, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	loginURL := "https://webprosindia.com/vignanit/Default.aspx"

	resp, err := client.Get(loginURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get login page: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	viewState, eventValidation, err := extractHiddenFields(bodyBytes)
	if err != nil {
		return nil, err
	}

	encryptedPassword, err := encryptPasswordAES(password)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("__VIEWSTATE", viewState)
	data.Set("__EVENTVALIDATION", eventValidation)
	data.Set("txtId2", username)
	data.Set("hdnpwd2", encryptedPassword)
	data.Set("imgBtn2.x", "25")
	data.Set("imgBtn2.y", "10")

	req, _ := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp2, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	loginBodyBytes, _ := io.ReadAll(resp2.Body)

	if strings.Contains(string(loginBodyBytes), "Invalid Username") {
		return nil, fmt.Errorf("invalid login")
	}

	return client, nil
}

// Restored original attendance function with proper parsing
func FetchAttendanceAPI(username, password string) AttendanceResponse {
	client, err := authenticateUser(username, password)
	if err != nil {
		return AttendanceResponse{Error: err.Error()}
	}

	attendanceURL := "https://webprosindia.com/vignanit/Academics/studentacadamicregister.aspx?scrid=2"

	resp3, err := client.Get(attendanceURL)
	if err != nil {
		return AttendanceResponse{Error: err.Error()}
	}
	defer resp3.Body.Close()
	doc, err := goquery.NewDocumentFromReader(resp3.Body)
	if err != nil {
		return AttendanceResponse{Error: err.Error()}
	}

	today := getCurrentDate()
	totalPresent, totalClasses := 0, 0
	todaysAttendance := []string{}
	subjectAttendance := []string{}

	// Find headers to locate today's column (original logic)
	headerRow := doc.Find("tr.reportHeading2WithBackground")
	headers := []string{}
	headerRow.Find("td").Each(func(i int, s *goquery.Selection) {
		headers = append(headers, strings.TrimSpace(s.Text()))
	})
	todayIndex := -1
	for i, h := range headers {
		if strings.Contains(h, today) {
			todayIndex = i
			break
		}
	}

	// Process attendance rows (original logic restored)
	doc.Find("tr[title]").Each(func(i int, s *goquery.Selection) {
		cells := s.Find("td.cellBorder")
		if cells.Length() < 2 {
			return
		}
		subject := strings.TrimSpace(cells.Eq(1).Text())
		attendance := strings.TrimSpace(cells.Eq(cells.Length() - 2).Text())
		percent := strings.TrimSpace(cells.Eq(cells.Length() - 1).Text())

		var present, total int
		if strings.Contains(attendance, "/") {
			fmt.Sscanf(attendance, "%d/%d", &present, &total)
		}
		totalPresent += present
		totalClasses += total

		// Check today's attendance (original logic)
		if todayIndex != -1 && todayIndex < cells.Length() {
			todayText := strings.TrimSpace(cells.Eq(todayIndex).Text())
			statuses := []string{}
			for _, s := range strings.Fields(todayText) {
				if s == "P" || s == "A" {
					statuses = append(statuses, s)
				}
			}
			if len(statuses) > 0 {
				todaysAttendance = append(todaysAttendance, fmt.Sprintf("%s: %s", subject, strings.Join(statuses, " ")))
			}
		}
		subjectAttendance = append(subjectAttendance, fmt.Sprintf("%-20s %7s %s", subject, attendance, percent))
	})

	overallPercentage := 0.0
	if totalClasses > 0 {
		overallPercentage = float64(totalPresent) / float64(totalClasses) * 100
	}

	skippable := calculateSkippableHours(totalPresent, totalClasses)
	required := calculateRequiredHours(totalPresent, totalClasses)

	return AttendanceResponse{
		StudentID:         username,
		TotalPresent:      totalPresent,
		TotalClasses:      totalClasses,
		OverallPercentage: overallPercentage,
		TodaysAttendance:  todaysAttendance,
		SubjectAttendance: subjectAttendance,
		SkippableHours:    skippable,
		RequiredHours:     required,
	}
}

// Keep your timetable function unchanged
func FetchTimetableAPI(username, password string) TimetableResponse {
	client, err := authenticateUser(username, password)
	if err != nil {
		return TimetableResponse{Error: err.Error()}
	}

	ajaxURL := "https://webprosindia.com/vignanit/ajax/Academics_TimeTableReport,App_Web_timetablereport.aspx.a2a1b31c.ashx?_method=getTimeTableReport&_session=r"

	req, err := http.NewRequest("GET", ajaxURL, nil)
	if err != nil {
		return TimetableResponse{Error: fmt.Sprintf("request error: %v", err)}
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return TimetableResponse{Error: fmt.Sprintf("request failed: %v", err)}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return TimetableResponse{Error: fmt.Sprintf("failed to read response: %v", err)}
	}

	rawStr := string(bodyBytes)
	start := strings.Index(rawStr, "'")
	end := strings.LastIndex(rawStr, "'")
	if start == -1 || end == -1 || end <= start {
		return TimetableResponse{Error: "No valid HTML found in AJAX response"}
	}
	htmlStr := rawStr[start+1 : end]

	if htmlStr == "" {
		return TimetableResponse{Error: "empty HTML content in AJAX response"}
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		return TimetableResponse{Error: fmt.Sprintf("failed to parse HTML: %v", err)}
	}

	schedule := []DaySchedule{}
	subjects := []Subject{}

	tables := doc.Find("table")

	if tables.Length() < 2 {
		return TimetableResponse{Error: "expected timetable and subject tables not found"}
	}

	var subjectTable *goquery.Selection

	tables.Each(func(i int, table *goquery.Selection) {
		headerRow := table.Find("tr").First()
		if strings.Contains(headerRow.Text(), "Subject Code") {
			subjectTable = table
		}
	})

	if subjectTable != nil {
		subjectTable.Find("tr").Each(func(i int, row *goquery.Selection) {
			if i == 0 {
				return // Skip header
			}
			cells := row.Find("td")
			if cells.Length() >= 3 {
				subject := Subject{
					Code:    strings.TrimSpace(cells.Eq(0).Text()),
					Name:    strings.TrimSpace(cells.Eq(1).Text()),
					Faculty: strings.TrimSpace(cells.Eq(2).Text()),
				}
				subjects = append(subjects, subject)
			}
		})
	}

	var timetableTable *goquery.Selection

	tables.Each(func(i int, table *goquery.Selection) {
		headerRow := table.Find("tr").First()
		if strings.Contains(headerRow.Text(), "Day of week") {
			timetableTable = table
		}
	})

	if timetableTable == nil {
		return TimetableResponse{Error: "timetable not found"}
	}

	headerCells := timetableTable.Find("tr").First().Find("td")
	var timeSlots []TimeSlot

	headerCells.Each(func(i int, cell *goquery.Selection) {
		if i == 0 {
			return // Skip "Day of week" column
		}
		cellHTML, _ := cell.Html()
		timeSlot := parseTimeSlot(cellHTML)
		timeSlots = append(timeSlots, timeSlot)
	})

	timetableTable.Find("tr").Each(func(i int, row *goquery.Selection) {
		if i == 0 {
			return // Skip header
		}

		cells := row.Find("td")
		if cells.Length() < 2 {
			return
		}

		day := strings.TrimSpace(cells.First().Text())
		periods := []PeriodDetail{}

		for j := 1; j < cells.Length(); j++ {
			timeSlotIdx := j - 1
			if timeSlotIdx >= len(timeSlots) {
				break
			}
			subjectCode := strings.TrimSpace(cells.Eq(j).Text())
			faculty := ""
			if subjectCode != "" && subjectCode != "&nbsp;" && !strings.Contains(strings.ToLower(subjectCode), "nbsp") {
				faculty = findFacultyForSubject(subjectCode, subjects)
			}
			period := PeriodDetail{
				TimeSlot: timeSlots[timeSlotIdx],
				Subject:  subjectCode,
				Faculty:  faculty,
			}
			periods = append(periods, period)
		}

		if day != "" && len(periods) > 0 {
			schedule = append(schedule, DaySchedule{
				Day:     day,
				Periods: periods,
			})
		}
	})

	return TimetableResponse{
		StudentID: username,
		Schedule:  schedule,
		Subjects:  subjects,
	}
}

// --- HTTP Handlers & Main ---

func attendanceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp := FetchAttendanceAPI(req.Username, req.Password)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func timetableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp := FetchTimetableAPI(req.Username, req.Password)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func performSelfCheck() {
	healthURL := "http://localhost:8080/health"
	fmt.Println("Performing self-health-check...")

	resp, err := http.Get(healthURL)
	if err != nil {
		fmt.Printf("Self-check failed, couldn't reach server: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Self-check successful: Server is healthy.")
	} else {
		fmt.Printf("Self-check failed with status: %s\n", resp.Status)
	}
}

func main() {
	ticker := time.NewTicker(3 * time.Minute)
	go func() {
		for range ticker.C {
			performSelfCheck()
		}
	}()

	http.HandleFunc("/attendance", attendanceHandler)
	http.HandleFunc("/timetable", timetableHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("Server started at :8080")
	fmt.Println("Available endpoints:")
	fmt.Println("  POST /attendance - Get attendance data")
	fmt.Println("  POST /timetable - Get timetable data")
	fmt.Println("  GET  /health     - Health check endpoint")
	fmt.Println("Self-health-check scheduled to run every 3 minutes.")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
