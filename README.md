# Custom Golang HTTP Router

## Prerequisite
Read tour of go before you read this blog
Read through the net/http package. If the doc is too intimidating watch Undestanding the net/http package video by Todd McLeod.
Please refer to this github repository for the implementation
Basically, a HTTP router is sort of a multiplexer. It routes the HTTP request to the code that handles the request. gorilla/mux is a commonly used router in golang. The golang standard library offers ServeMUX to do the same.

For the sake of understanding how we design the router, lets consider the following. A router is a collection of routes and a route will have the following:
1. Path
2. Method (GET/POST/PUT/DELETE)
3. Handler
   
So we can have two structs:

```type Route struct {
   Method  string
   Pattern string
   Handler http.Handler
}

type Router struct {
   routes          []Route
}```

We should be able to create a new router and register the routes. To be able to create a new router we need a method NewRouter.

```func NewRouter() *Router {
   return &Router{}
}```

To be able to register the routes we need the methods GET, POST & DELETE. All of the methods will call AddRoute which will append to routes.

```func (r *Router) AddRoute(method, path string, handler http.Handler) {
   r.routes = append(r.routes, Route{Method: method, Pattern: path, Handler: handler})
}```

Then the methods which will call AddRoute:

func (r *Router) GET(path string, handler Handler) {
   r.AddRoute("GET", path, handler)
}

func (r *Router) POST(path string, handler Handler) {
   r.AddRoute("POST", path, handler)
}

func (r *Router) DELETE(path string, handler Handler) {
   r.AddRoute("DELETE", path, handler)
}

Note : In the above methods, Instead of accepting an http.Handler , we used a type Handler which implements handler interface. The reason being, if we used http.Handler we would end up implementing ServeHTTP for each of our handlers in our application.

So we can define our own handler type
```
type Handler func(r *http.Request) (statusCode int, data map[string]interface{})
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
 statusCode, data := h(r)
 w.WriteHeader(statusCode)
json.NewEncoder(w).Encode(data)
}
```

This also allows us to standardise the way we send our responses back to the client.

Now we can register our routes, but how do we allow the server to use the router to call the respective handler?

ListenAndServe is used to start a server, and the ListenAndServe function takes in two parameters — addr and handler.
```
func ListenAndServe(addr string, handler Handler) error
We need to do two things here
```

We need a method which matches the route and calls the respective handler.
We need our router to be of type handler so we need to implement the handler interface, so our router can be passed as a handler in ListenAndServe. (If you don’t understand this step please look at this video by Todd McLeod in his youtube channel Learn To Code — He explains Understanding Golang net/http package)

So let’s write a method getHandler which iterates through our routes to find which handler needs to be called.

```
func (r *Router) getHandler(method, path string) http.Handler {
   for _, route := range r.routes {
      re := regexp.MustCompile(route.Pattern)
      if route.Method == method && re.MatchString(path){
         return route.Handler
      }
   }
   return http.NotFoundHandler()
}
```

To implement the Handler interface we need to have ServeHTTP(ResponseWriter, *Request) method in our router which will make our Router a Handler type which we can pass into ListenAndServe.

So we implement ServeHTTP method
```
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request){
   path := req.URL.Path
   method := req.Method

   handler := r.getHandler(method, path)

   // handler middlewares go here

   handler.ServeHTTP(w, req)
}
```
Red line shows how a handler from application is registered before the server is run
The Custom Handler will be the handlers we define in our application
Green line shows how a server finds a registered handler
We pass our router in ListenAndServe, and our router implements handler interface. So the ServeHTTP method will call getRoute which will return the application handler which is of the custom handler type we have written.
Benefit of having your own custom HTTP router:

You can define your own standard for response formats
You can have a preset of middleware validations. Now you can concentrate on business logic after this.
Some examples of preset middleware that you can implement
1. CORS
2. You can write a middleware to calculate time taken by the particular request