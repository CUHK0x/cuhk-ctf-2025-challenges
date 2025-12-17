let json_response ?status content = content |> Yojson.Safe.to_string |> Dream.json ?status

let json_receiver json_parser handler request =
  let%lwt body = Dream.body request in
  let parse =
    try Some (body |> Yojson.Safe.from_string |> json_parser) with
    | _ -> None
  in
  match parse with
  | Some doc -> handler doc request
  | None ->
    { error = "Received invalid JSON input." }
    |> Doc.Error_doc.yojson_of_t
    |> json_response ~status:`Bad_Request
;;
