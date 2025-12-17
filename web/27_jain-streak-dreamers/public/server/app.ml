let () =
  Dream.run ~interface:"0.0.0.0" ~port:8080
  @@ Dream.logger
  @@ Dream.sql_pool "sqlite3:db.sqlite"
  @@ Dream.memory_sessions
  @@ Dream.router
       [ Dream.scope
           "/api"
           []
           [ Dream.get "" Api.Home.get
           ; Dream.get "/echo/:word" Api.Echo.get
           ; Dream.get "/things" Api.Thing.get_all
           ; Dream.post "/things" Api.Thing.create
           ; Dream.post "/users/login" Api.User.login
           ; Dream.post "/users/logout" Api.User.logout
           ; Dream.get "/users/me" Api.User.me
           ; Dream.post "/users/register" Api.User.register
           ; Dream.scope
               "/uploads"
               [ Utils.Authorize.check_authorized ]
               [ Dream.get "/:upload_id" Api.Uploads.get
               ; Dream.get "" Api.Uploads.get_all
               ; Dream.post "" Api.Uploads.post
               ]
           ]
       ; Dream.scope
           ""
           []
           [ Dream.get "/" Views.Home.handler
           ; Dream.get "/login" Views.Login.handler
           ; Dream.get "/register" Views.Register.handler
           ; Dream.get "/gallery" Views.Gallery.handler
           ; Dream.get "/static/**" @@ Dream.static "./static"
           ; Dream.get "/uploads/**" @@ Dream.static "./uploads"
           ]
       ]
;;
