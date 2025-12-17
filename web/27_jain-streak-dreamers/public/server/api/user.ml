let login =
  let login_success (user : Models.User.t) request =
    let%lwt () = Dream.invalidate_session request in
    let%lwt () = Dream.set_session_field request "user" user.username in
    user |> Models.User.yojson_of_t |> Utils.Json.json_response
  in
  let handler (read_doc : Doc.User_read_doc.t) request =
    let%lwt user = Dream.sql request (Models.User.read read_doc) in
    match user with
    | None ->
      Utils.Error.send_error ~status:`Not_Found "User not found or password incorrect"
    | Some user ->
      let verdict = Utils.Hasher.verify user.password read_doc.password in
      if not verdict
      then
        Utils.Error.send_error
          ~status:`Unauthorized
          "User not found or password incorrect"
      else login_success user request
  in
  Utils.Json.json_receiver Doc.User_read_doc.t_of_yojson handler
;;

let logout request =
  let%lwt () = Dream.invalidate_session request in
  Dream.empty `No_Content
;;

let me request =
  match Dream.session_field request "user" with
  | None -> Utils.Error.send_error ~status:`Not_Found "User not found"
  | Some username ->
    let%lwt user = Dream.sql request (Models.User.read { username; password = "" }) in
    (match user with
     | None -> Utils.Error.send_error ~status:`Not_Found "User not found"
     | Some user -> user |> Models.User.yojson_of_t |> Utils.Json.json_response)
;;

let register =
  let handler (create_doc : Doc.User_create_doc.t) request =
    let%lwt existing_user =
      Dream.sql
        request
        (Models.User.read { username = create_doc.username; password = "" })
    in
    match existing_user with
    | None ->
      let%lwt user = Dream.sql request (Models.User.create create_doc) in
      user |> Models.User.yojson_of_t |> Utils.Json.json_response ~status:`Created
    | Some _ -> Utils.Error.send_error "User already exists"
  in
  Utils.Json.json_receiver Doc.User_create_doc.t_of_yojson handler
;;
