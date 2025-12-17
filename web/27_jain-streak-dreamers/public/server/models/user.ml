open Ppx_yojson_conv_lib.Yojson_conv.Primitives

module type DB = Caqti_lwt.CONNECTION

module T = Caqti_type

type t =
  { id : int
  ; username : string
  ; password : string
  }
[@@deriving yojson]

let db_create =
  let query =
    let open Caqti_request.Infix in
    (T.(t2 string string) ->. T.unit)
      {|
    INSERT INTO users (username, password) 
    VALUES ($1, $2)
    |}
  in
  fun username hashed_password (module Db : DB) ->
    let%lwt result = Db.exec query (username, hashed_password) in
    Caqti_lwt.or_fail result
;;

let db_read =
  let query =
    let open Caqti_request.Infix in
    (T.string ->? T.(t3 int string string))
      {|
    SELECT id, username, password FROM users WHERE username = $1
    |}
  in
  fun username (module Db : DB) ->
    let%lwt result = Db.find_opt query username in
    Caqti_lwt.or_fail result
;;

let create (create_doc : Doc.User_create_doc.t) (db : (module DB)) =
  let hashed_password = Utils.Hasher.hash create_doc.password in
  let%lwt _ = db_create create_doc.username hashed_password db in
  let%lwt user_opt = db_read create_doc.username db in
  match user_opt with
  | None -> raise (Failure "User creation failed")
  | Some (id, username, password) -> Lwt.return { id; username; password }
;;

let read (read_doc : Doc.User_read_doc.t) (db : (module DB)) =
  let%lwt user_opt = db_read read_doc.username db in
  match user_opt with
  | None -> Lwt.return_none
  | Some (id, username, password) -> Lwt.return_some { id; username; password }
;;
