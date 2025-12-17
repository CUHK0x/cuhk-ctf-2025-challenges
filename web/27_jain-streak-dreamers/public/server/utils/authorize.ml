let check_authorized inner_handler request =
  let user_opt = Dream.session_field request "user" in
  match user_opt with
  | None -> Error.send_error ~status:`Unauthorized "Unauthorized"
  | Some _ -> inner_handler request
;;
