let get _ =
  let version = 1 in
  let description = "Hello World!" in
  { Doc.Home_doc.version; Doc.Home_doc.description }
  |> Doc.Home_doc.yojson_of_t
  |> Utils.Json.json_response
;;
