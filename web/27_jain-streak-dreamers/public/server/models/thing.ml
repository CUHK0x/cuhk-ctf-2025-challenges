open Ppx_yojson_conv_lib.Yojson_conv.Primitives

module type DB = Caqti_lwt.CONNECTION

module T = Caqti_type

type t =
  { timestamp : int
  ; content : string
  }
[@@deriving yojson]

let db_create =
  let query =
    let open Caqti_request.Infix in
    (T.(t2 int string) ->. T.unit)
      {|
    INSERT INTO things (timestamp, content) 
    VALUES ($1, $2)
    |}
  in
  fun timestamp content (module Db : DB) ->
    let%lwt result = Db.exec query (timestamp, content) in
    Caqti_lwt.or_fail result
;;

let db_read_all =
  let query =
    let open Caqti_request.Infix in
    (T.unit ->* T.(t2 int string))
      {|
    SELECT timestamp, content FROM things
    |}
  in
  fun (module Db : DB) ->
    let%lwt result = Db.collect_list query () in
    Caqti_lwt.or_fail result
;;

let create (create_doc : Doc.Thing_create_doc.t) (db : (module DB)) =
  let timestamp = Unix.time () |> Float.to_int in
  let%lwt _ = db_create timestamp create_doc.content db in
  Lwt.return { timestamp; content = create_doc.content }
;;

let read_all db =
  let%lwt things = db_read_all db in
  Lwt.return (List.map (fun (timestamp, content) -> { timestamp; content }) things)
;;
