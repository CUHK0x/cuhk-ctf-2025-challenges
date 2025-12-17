let handler request =
  let username =
    match Dream.session_field request "user" with
    | Some u -> u
    | _ -> "Guest"
  in
  username |> Templates.Home.render |> Templates.Base.render |> Dream.html
;;
