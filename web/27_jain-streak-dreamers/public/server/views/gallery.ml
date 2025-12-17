let handler request =
  match Dream.session_field request "user" with
  | Some user ->
    Templates.Gallery.render request user |> Templates.Base.render |> Dream.html
  | _ -> Dream.redirect request "/login"
;;
