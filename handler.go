package porcupineapi

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type Handler struct {
	AuthConfig  *oauth2.Config
	Store       *sessions.CookieStore
	UserInfoURL string
	Audience    string
}

type AuthToken struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// IDToken is the token that authorizes and authenticates
	// the requests.
	IDToken string `json:"id_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// raw optionally contains extra metadata from the server
	// when updating a token.
	raw interface{}

	// expiryDelta is used to calculate when a token is considered
	// expired, by subtracting from Expiry. If zero, defaultExpiryDelta
	// is used.
	expiryDelta time.Duration
}

func NewHandler(envVars EnvVars, store *sessions.CookieStore) *Handler {
	authConfig := &oauth2.Config{
		RedirectURL:  envVars.CallbackURL,
		ClientID:     envVars.Auth0ClientID,
		ClientSecret: envVars.Auth0ClientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", envVars.Auth0Domain),
			TokenURL: fmt.Sprintf("https://%s/oauth/token", envVars.Auth0Domain),
		},
	}
	userInfoURL := fmt.Sprintf("https://%s/userinfo", envVars.Auth0Domain)
	audience := "https://api.porcupine.co.za"
	return &Handler{AuthConfig: authConfig, Store: store, UserInfoURL: userInfoURL, Audience: audience}
}

func (h *Handler) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate secure random state
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			http.Error(w, "Failed to generate secure state", http.StatusInternalServerError)
			return
		}
		state := base64.StdEncoding.EncodeToString(b)

		// Store state in session
		session, _ := h.Store.Get(r, "session-name")
		session.Values["state"] = state
		session.Save(r, w)

		// Redirect user
		url := h.AuthConfig.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (h *Handler) CallbackHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the state from the session
		session, err := h.Store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		storedState, ok := session.Values["state"].(string)
		if !ok {
			http.Error(w, "State not found in session", http.StatusBadRequest)
			return
		}

		// Compare the state in the callback with the stored state
		callbackState := r.URL.Query().Get("state")
		if callbackState != storedState {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// Manually craft the token request with the "audience"
		tokenURL := h.AuthConfig.Endpoint.TokenURL
		values := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {r.URL.Query().Get("code")},
			"redirect_uri":  {h.AuthConfig.RedirectURL},
			"client_id":     {h.AuthConfig.ClientID},
			"client_secret": {h.AuthConfig.ClientSecret},
			"audience":      {h.Audience}, // Add the audience here
		}

		resp, err := http.PostForm(tokenURL, values)
		if err != nil {
			log.Printf("Token request failed: %s\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Token request returned status: %d\n", resp.StatusCode)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		token := new(AuthToken)
		if err := json.NewDecoder(resp.Body).Decode(token); err != nil {
			log.Printf("Failed to decode token response: %s\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		oauth2Token := oauth2.Token{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
			Expiry:      token.Expiry,
		}

		ctx := r.Context()
		client := h.AuthConfig.Client(ctx, &oauth2Token)
		userInfoResponse, err := client.Get(h.UserInfoURL)
		if err != nil {
			log.Printf("Failed to get user info: %s\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer userInfoResponse.Body.Close()

		// Read user information response
		userInfo, err := io.ReadAll(userInfoResponse.Body)
		if err != nil {
			log.Printf("Failed to read user info: %s\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		// Prepare the combined response including user info and the token
		responseData := map[string]interface{}{
			"user_info": json.RawMessage(userInfo),
			"token": map[string]interface{}{
				"access_token": token.AccessToken,
				"id_token":     token.IDToken,
				"token_type":   token.TokenType,
				"expires_in":   token.Expiry.Sub(time.Now()).Seconds(), // time left until token expiry
			},
		}

		responseJSON, err := json.Marshal(responseData)
		if err != nil {
			log.Printf("Failed to marshal response: %s\n", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(responseJSON)
	}
}

/*
 * Implementation of SELECT * FROM tableName
 */
func GetAllHandler(db *sql.DB, tables Tables) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		var rows *sql.Rows
		var err error

		if tables.LinkTable2 != "" {
			// Complex query involving joins and parameterization
			query := `SELECT * FROM ` + tables.MainTable + ` mt ` +
				`LEFT JOIN ` + tables.LinkTable1 + ` lt1 ON lt1.` + tables.LinkID1 + ` = mt.` + tables.LinkID1 + ` ` +
				`LEFT JOIN ` + tables.LinkTable2 + ` lt2 ON lt2.` + tables.LinkID2 + ` = mt.` + tables.LinkID2 + ` ` +
				`WHERE mt.` + tables.LinkID1 + ` = ?`

			// Prepare the query to avoid SQL injection in the WHERE clause
			stmt, err := db.Prepare(query)
			if err != nil {
				log.Printf("db.Prepare Error: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Execute the query with the parameterized institution ID
			rows, err = stmt.Query(vars[tables.LinkID1])
		} else {
			// Simple query with no parameterization
			query := `SELECT * FROM ` + tables.MainTable

			// Execute the simple query
			rows, err = db.Query(query)
		}

		if err != nil {
			log.Printf("db.Query Error: %v", err.Error())
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			log.Printf("rows.Columns Error: %v", err.Error())
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}

		var results []map[string]interface{}
		for rows.Next() {
			err := rows.Scan(pointers...)
			if err != nil {
				log.Printf("rows.Scan Error: %v", err.Error())
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}

			entry := make(map[string]interface{})
			for i, colName := range columns {
				val := pointers[i].(*interface{})
				if *val == nil {
					entry[colName] = "null" // Or use any other placeholder
				} else if b, ok := (*val).([]byte); ok {
					entry[colName] = string(b)
				} else {
					entry[colName] = *val
				}
			}
			results = append(results, entry)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}

/*
 * Implementation of SELECT * FROM tableName WHERE id = {id}
 */
func GetByIDHandler(db *sql.DB, tables Tables) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		var rows *sql.Rows
		var err error

		if tables.LinkTable2 != "" {
			// Complex query involving joins and parameterization
			// /institutions/{id}/users/{id}
			query := `SELECT * FROM ` + tables.MainTable + ` mt ` +
				`LEFT JOIN ` + tables.LinkTable1 + ` lt1 ON lt1.` + tables.LinkID1 + ` = mt.` + tables.LinkID1 + ` ` +
				`LEFT JOIN ` + tables.LinkTable2 + ` lt2 ON lt2.` + tables.LinkID2 + ` = mt.` + tables.LinkID2 + ` ` +
				`WHERE mt.` + tables.LinkID1 + ` = ?` + ` ` +
				`AND mt.` + tables.LinkID2 + ` = ?`

			// Prepare the query to avoid SQL injection in the WHERE clause
			stmt, err := db.Prepare(query)
			if err != nil {
				log.Printf("db.Prepare Error: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Execute the query with the parameterized institution ID
			rows, err = stmt.Query(vars[tables.LinkID1], vars[tables.LinkID2])
		} else {
			// Simple query with no parameterization
			// /institutions/{id}
			query := `SELECT * FROM ` + tables.MainTable + ` mt ` +
				`WHERE mt.` + tables.LinkID1 + ` = ?`

			// Prepare the query to avoid SQL injection in the WHERE clause
			stmt, err := db.Prepare(query)
			if err != nil {
				log.Printf("db.Prepare Error: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Execute the query with the parameterized institution ID
			rows, err = stmt.Query(vars[tables.LinkID1])
		}

		if err != nil {
			log.Printf("db.Query Error: %v", err.Error())
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		columns, err := rows.Columns()
		if err != nil {
			log.Printf("rows.Columns Error: %v", err.Error())
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}

		var results []map[string]interface{}
		for rows.Next() {
			err := rows.Scan(pointers...)
			if err != nil {
				log.Printf("rows.Scan Error: %v", err.Error())
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}

			entry := make(map[string]interface{})
			for i, colName := range columns {
				val := pointers[i].(*interface{})
				if *val == nil {
					entry[colName] = "null" // Or use any other placeholder
				} else if b, ok := (*val).([]byte); ok {
					entry[colName] = string(b)
				} else {
					entry[colName] = *val
				}
			}
			results = append(results, entry)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}

/*
 * Implementation of INSERT INTO tableName
 */
func CreateHandler(db *sql.DB, tables Tables) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read and parse JSON body into a map
		var data map[string]interface{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(body, &data); err != nil {
			log.Printf("Error unmarshaling JSON: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Fetch column names and properties from the database table
		columns, err := getTableColumns(db, tables.MainTable)
		if err != nil {
			log.Printf("Error fetching table columns: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Filter JSON data to match database schema and prepare SQL statement
		columnNames := make([]string, 0, len(data))
		placeholders := make([]string, 0, len(data))
		values := make([]interface{}, 0, len(data))

		for key, val := range data {
			col, exists := columns[key]
			if exists && !col.IsAutoIncrement {
				columnNames = append(columnNames, key)
				placeholders = append(placeholders, "?")
				values = append(values, val)
			}
		}

		if len(columnNames) == 0 {
			log.Printf("No valid columns provided for insertion")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		insertQuery := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			tables.MainTable,
			strings.Join(columnNames, ", "),
			strings.Join(placeholders, ", "),
		)

		stmt, err := db.Prepare(insertQuery)
		if err != nil {
			log.Printf("Error preparing insert: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		res, err := stmt.Exec(values...)
		if err != nil {
			log.Printf("Error executing insert: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		lastInsertId, err := res.LastInsertId()
		if err != nil {
			log.Printf("Error retrieving last insert ID: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(fmt.Sprintf(`{"message": "Creation successful", `+tables.LinkID1+`: %d}`, lastInsertId)))
	}
}

/*
 * Implementation of UPDATE tableName SET ... WHERE id = {id}
 */
func UpdateHandler(db *sql.DB, tables Tables) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read and parse JSON body into a map
		var data map[string]interface{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(body, &data); err != nil {
			log.Printf("Error unmarshaling JSON: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Fetch column names from the database table
		columns, err := getTableColumns(db, tables.MainTable)
		if err != nil {
			log.Printf("Error fetching table columns: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Prepare SQL statement using only valid columns from JSON
		setClauses := make([]string, 0, len(data))
		values := make([]interface{}, 0, len(data)+1) // +1 for the ID at the end
		for key, val := range data {
			if _, exists := columns[key]; exists {
				setClause := fmt.Sprintf("%s = ?", key)
				setClauses = append(setClauses, setClause)
				values = append(values, val)
			}
		}

		// Extract and append ID for the WHERE clause
		id, ok := data[tables.LinkID1]
		if !ok || len(setClauses) == 0 {
			log.Printf("No ID provided or no valid columns for update")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		values = append(values, id)

		updateQuery := fmt.Sprintf("UPDATE %s SET %s WHERE %s = ?",
			tables.MainTable,
			strings.Join(setClauses, ", "),
			tables.LinkID1,
		)

		stmt, err := db.Prepare(updateQuery)
		if err != nil {
			log.Printf("Error preparing update: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		_, err = stmt.Exec(values...)
		if err != nil {
			log.Printf("Error executing update: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Inform the client that the update was successful
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Update successful"}`))
	}
}

/*
 * Implementation of DELETE FROM tableName WHERE id = {id}
 */
func DeleteHandler(db *sql.DB, tables Tables) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extracting the institution_id from the URL using Gorilla mux
		vars := mux.Vars(r)
		idStr, ok := vars[tables.LinkID1]
		if !ok {
			http.Error(w, "Missing "+tables.LinkID1+" in URL", http.StatusBadRequest)
			return
		}

		// Convert the institution_id from string to int
		deleteID, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid "+tables.LinkID1, http.StatusBadRequest)
			return
		}

		// Prepare the SQL statement for deleting the entry
		deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE %s = ?", tables.MainTable, tables.LinkID1)

		// Execute the deletion
		res, err := db.Exec(deleteQuery, deleteID)
		if err != nil {
			log.Printf("Error executing delete: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check how many rows were affected
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			log.Printf("Error fetching rows affected: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if rowsAffected == 0 {
			http.Error(w, "No "+tables.MainTable+" found with given ID", http.StatusNotFound)
			return
		}

		// Respond to the client
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, tables.MainTable+" "+idStr+" id deleted successfully")
	}
}

// getTableColumns retrieves a map of column names and properties for a given table
func getTableColumns(db *sql.DB, tableName string) (map[string]struct{ IsAutoIncrement bool }, error) {
	columns := make(map[string]struct{ IsAutoIncrement bool })
	// Prepare the query to fetch column details
	query := fmt.Sprintf("SHOW COLUMNS FROM %s", tableName)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		colName    string
		colType    string
		colNull    string
		colKey     string
		colDefault sql.NullString
		colExtra   string
	)

	// Iterate over all rows
	for rows.Next() {
		// Scan all columns. Note that we need placeholders for every column fetched.
		if err := rows.Scan(&colName, &colType, &colNull, &colKey, &colDefault, &colExtra); err != nil {
			return nil, err
		}
		// Check if the column is auto-increment
		columns[colName] = struct{ IsAutoIncrement bool }{
			IsAutoIncrement: strings.Contains(colExtra, "auto_increment"),
		}
	}

	// Check for any errors encountered during iteration
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return columns, nil
}
