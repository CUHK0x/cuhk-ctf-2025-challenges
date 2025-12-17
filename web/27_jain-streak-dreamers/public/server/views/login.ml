let handler request =
  match Dream.session_field request "user" with
  | Some _ -> Dream.redirect request "/"
  | _ -> "Guest" |> Templates.Login.render |> Templates.Base.render |> Dream.html
;;
