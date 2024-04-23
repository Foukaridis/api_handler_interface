package porcupineapi

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/PChoice-Development/porcupineapi/middleware"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type Router struct {
	router  *mux.Router
	db      *sql.DB
	handler *Handler
}

type Tables struct {
	FormattedRoute string
	MainTable      string
	LinkTable1     string
	LinkID1        string
	LinkTable2     string
	LinkID2        string
}

type EnvVars struct {
	Environment       string `env:"APP_ENV,required"`
	Auth0Domain       string `env:"AUTH0_DOMAIN,required"`
	Auth0ClientID     string `env:"AUTH0_CLIENT_ID,required"`
	Auth0ClientSecret string `env:"AUTH0_CLIENT_SECRET,required"`
	CallbackURL       string `env:"CALLBACK,required"`
}

func NewRouter(db *Database, envVars EnvVars, store *sessions.CookieStore) *Router {
	middleware.Auth0ClientID = envVars.Auth0ClientID
	middleware.Auth0Domain = envVars.Auth0Domain
	middleware.Auth0ClientSecret = envVars.Auth0ClientSecret

	return &Router{
		router:  mux.NewRouter(),
		db:      db.db,
		handler: NewHandler(envVars, store),
	}
}

func applyMiddlewares(handler http.Handler, useAuth bool) http.Handler {
	// Apply logging to all routes
	handler = middleware.Logging(handler)
	// Apply CORS to all routes
	handler = middleware.CORSMiddleware(handler)
	// Conditionally apply OAuth token validation
	if useAuth {
		handler = middleware.OAuthTokenValidationMiddleware(handler)
	}
	return handler
}
func chainMiddlewares(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for _, middleware := range middlewares {
		handler = middleware(handler)
	}
	return handler
}
func (router *Router) LoadRoutes(filepath string, db *sql.DB) error {
	// Read the whole file at once using os.ReadFile
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err // Return the error to be handled by the caller
	}

	// Setup routes that do not require OAuth middleware
	router.router.Handle("/login", chainMiddlewares(http.HandlerFunc(router.handler.LoginHandler()), middleware.CORSMiddleware, middleware.Logging))
	router.router.Handle("/callback", chainMiddlewares(http.HandlerFunc(router.handler.CallbackHandler(db)), middleware.CORSMiddleware, middleware.Logging))

	// Convert the file content into a string and split into lines
	routes := strings.Split(string(data), "\n")

	for _, routeName := range routes {
		if routeName == "/login" || routeName == "/callback" {
			continue // Skip setup for these routes as they are already configured
		}
		tables := inferTableNames(routeName)
		setupRoute(router, db, tables)
	}

	return nil
}

func setupRoute(r *Router, db *sql.DB, tables Tables) {

	path := ""
	if tables.LinkTable2 == "" {
		path = tables.FormattedRoute + "/{" + tables.LinkID1 + "}"
	} else {
		path = tables.FormattedRoute + "/{" + tables.LinkID2 + "}"
	}

	// Apply middleware and configure handlers for each route
	r.router.Handle(tables.FormattedRoute, chainMiddlewares(http.HandlerFunc(GetAllHandler(db, tables)),
		middleware.CORSMiddleware,
		middleware.OAuthTokenValidationMiddleware,
		middleware.Logging)).Methods("GET")
	r.router.Handle(path, chainMiddlewares(http.HandlerFunc(GetByIDHandler(db, tables)),
		middleware.CORSMiddleware,
		middleware.OAuthTokenValidationMiddleware,
		middleware.Logging)).Methods("GET")
	r.router.Handle(tables.FormattedRoute, chainMiddlewares(http.HandlerFunc(CreateHandler(db, tables)),
		middleware.CORSMiddleware,
		middleware.OAuthTokenValidationMiddleware,
		middleware.Logging)).Methods("POST")
	r.router.Handle(path, chainMiddlewares(http.HandlerFunc(UpdateHandler(db, tables)),
		middleware.CORSMiddleware,
		middleware.OAuthTokenValidationMiddleware,
		middleware.Logging)).Methods("PUT")
	r.router.Handle(path, chainMiddlewares(http.HandlerFunc(DeleteHandler(db, tables)),
		middleware.CORSMiddleware,
		middleware.OAuthTokenValidationMiddleware,
		middleware.Logging)).Methods("DELETE")

}

/*
	 	inferTableName processes the route like this:
		Route "/institutions/{id}/users":
	 	tables = split(routes, "/{id}/") = ["institutions", "users"]
	 	Link_table_name = replace(routes, "s/{id}/", "_") = institution_users.
		do a count of {id} in routes. here is 1. count -1 is index for tables
		remove trailing s from tables[0] = institution
		so id = tables[0]+"_id"
		Always use only {id} in the file for string matching
*/
func inferTableNames(route string) Tables {

	count := strings.Count(route, "s/{id}/")

	if count == 0 {
		mainTable := strings.ReplaceAll(route, "/", "")
		table := Tables{
			MainTable:      mainTable,
			LinkTable1:     "",
			LinkID1:        replaceTrailingS(mainTable),
			LinkTable2:     "",
			LinkID2:        "",
			FormattedRoute: route,
		}
		return table
	}

	// Replacing "s/{id}/" with "_" to get mainTable
	mainTable := strings.Replace(route, "s/{id}/", "_", 1)
	mainTable = strings.ReplaceAll(mainTable, "/", "")

	//User split to get the relevant join tables
	linkTables := strings.Split(route, "/{id}/")
	linkTable1 := strings.ReplaceAll(linkTables[0], "/", "")
	linkTable2 := strings.ReplaceAll(linkTables[1], "/", "")

	/*
	 * Loop through linkTables and Use TrimSuffix to replace the trailing s in the table names with _id to get the relevant ids
	 */

	// Slice to hold the modified table names
	linkIDs := make([]string, len(linkTables))
	for i, tableName := range linkTables {
		linkIDs[i] = replaceTrailingS(tableName)
		linkIDs[i] = strings.ReplaceAll(linkIDs[i], "/", "")
	}

	linkID1 := linkIDs[0]
	linkID2 := linkIDs[1]

	/*
	 * replace {id} with the relevant table id, eg: institutions/{id}/users should become institutions/{institution_id}/users
	 */
	idString := fmt.Sprintf("{%s}", linkID1)
	formattedRoute := strings.Replace(route, "{id}", idString, 1)

	tables := Tables{
		MainTable:      mainTable,
		LinkTable1:     linkTable1,
		LinkID1:        linkID1,
		LinkTable2:     linkTable2,
		LinkID2:        linkID2,
		FormattedRoute: formattedRoute,
	}

	return tables
}

// replaceTrailingS replaces the trailing 's' with '_id'.
func replaceTrailingS(s string) string {
	if strings.HasSuffix(s, "s") {
		return strings.TrimSuffix(s, "s") + "_id"
	}
	return s
}

func (r *Router) GetHandler() http.Handler {
	return r.router
}
