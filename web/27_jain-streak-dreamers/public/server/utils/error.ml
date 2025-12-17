let send_error ?(status = `Bad_Request) msg =
  { error = msg } |> Doc.Error_doc.yojson_of_t |> Json.json_response ~status
;;
