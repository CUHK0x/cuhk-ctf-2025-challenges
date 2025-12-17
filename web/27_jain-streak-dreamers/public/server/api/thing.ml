let get_all request =
  let%lwt things = Dream.sql request Models.Thing.read_all in
  `List (List.map Models.Thing.yojson_of_t things) |> Utils.Json.json_response
;;

let create =
  let handler create_doc request =
    let%lwt thing = Dream.sql request (Models.Thing.create create_doc) in
    thing |> Models.Thing.yojson_of_t |> Utils.Json.json_response ~status:`Created
  in
  Utils.Json.json_receiver Doc.Thing_create_doc.t_of_yojson handler
;;
