package porcupineapi

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	// Add your database connection fields here
	db *sql.DB
}

func NewDatabase(config Config) (*Database, *sql.DB, error) {
	// Initialize your database connection here
	connString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", config.DBUser, config.DBPass, config.DBHost, strconv.Itoa(config.DBPort), config.DBName)

	db, err := sql.Open("mysql", connString)
	if err != nil {
		return nil, nil, err
	}

	return &Database{db: db}, db, nil
}

func (d *Database) Close() {
	d.db.Close()
}

// Add your database operations here, such as querying or modifying data
func StoreUser(db *sql.DB, email, token string) {

	_, err := db.Exec("INSERT INTO users (email, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE token = ?", email, token, token)
	if err != nil {
		log.Fatal(err)
	}
}
