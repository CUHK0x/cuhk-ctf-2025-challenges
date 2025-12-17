let get request =
  let word = Dream.param request "word" in
  let response = { Models.Echo.word } in
  response |> Models.Echo.yojson_of_t |> Utils.Json.json_response
;;
