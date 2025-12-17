let uploads_root = Unix.realpath "uploads"

let search filepath =
  let realdir =
    try Some (filepath |> Filename.dirname |> Unix.realpath) with
    | Unix.Unix_error (Unix.ENOENT, _, _) -> None
  in
  match realdir with
  | None -> []
  | Some dir ->
    let filelist =
      dir |> Sys.readdir |> Array.to_list |> List.map (fun f -> Filename.concat dir f)
    in
    let glob =
      Filename.basename filepath |> Printf.sprintf "<%s>" |> Path_glob.Glob.parse ~dir
    in
    filelist |> List.filter (fun f -> Path_glob.Glob.eval glob f)
;;

type upload_mode =
  | Query
  | Download

let upload_mode_of_string = function
  | "query" -> Query
  | "download" -> Download
  | _ -> Download
;;

let get_query filepath =
  let filenames = search filepath |> List.map Filename.basename in
  let read_doc = { Doc.Upload_read_doc.filenames } in
  read_doc |> Doc.Upload_read_doc.yojson_of_t |> Utils.Json.json_response
;;

let get_one user_rootpath filepath =
  let realpath =
    match search filepath with
    | [] -> None
    | f :: _ -> Some f
  in
  match realpath with
  | None -> Utils.Error.send_error ~status:`Not_Found "File not found"
  | Some path ->
    if not (String.starts_with ~prefix:user_rootpath path)
    then Utils.Error.send_error ~status:`Forbidden "Access denied"
    else (
      let%lwt file_content =
        Lwt_io.with_file ~mode:Lwt_io.Input path (fun ic -> Lwt_io.read ic)
      in
      Dream.respond ~headers:[ "Content-Type", "application/octet-stream" ] file_content)
;;

let get request =
  let mode =
    match Dream.query request "mode" with
    | Some s -> s |> String.lowercase_ascii |> upload_mode_of_string
    | None -> Download
  in
  let upload_id = Dream.param request "upload_id" in
  let username =
    match Dream.session_field request "user" with
    | Some u -> u
    | _ -> raise (Failure "Unable to obtain user from session")
  in
  let%lwt user_opt = Dream.sql request (Models.User.read { username; password = "" }) in
  let current_user_id =
    match user_opt with
    | Some user -> user.id
    | None -> raise (Failure "Unable to obtain user from database")
  in
  let user_rootpath = Filename.concat uploads_root (string_of_int current_user_id) in
  let filepath = Filename.concat user_rootpath upload_id in
  match mode with
  | Query -> get_query filepath
  | Download -> get_one user_rootpath filepath
;;

let get_all request = Dream.redirect request "/api/uploads/*?mode=query"

type upload_result =
  | Upload_Ok
  | Upload_Too_Large
  | Upload_Forbidden
  | Upload_Invalid_Filename

let post request =
  let file_size_limit = 16 * 1024 in
  let username =
    match Dream.session_field request "user" with
    | Some u -> u
    | _ -> raise (Failure "Unable to obtain user from session")
  in
  let%lwt user_opt = Dream.sql request (Models.User.read { username; password = "" }) in
  let current_user_id =
    match user_opt with
    | Some user -> user.id
    | None -> raise (Failure "Unable to obtain user from database")
  in
  let rootpath = Filename.concat uploads_root (string_of_int current_user_id) in
  let try_save_file name_opt content =
    match name_opt with
    | None -> Lwt.return Upload_Invalid_Filename
    | Some "" -> Lwt.return Upload_Invalid_Filename
    | Some name ->
      let filepath =
        Filename.concat rootpath name |> Fpath.v |> Fpath.normalize |> Fpath.to_string
      in
      (match String.starts_with ~prefix:rootpath filepath with
       | false -> Lwt.return Upload_Forbidden
       | true ->
         let () =
           if not (Sys.file_exists rootpath && Sys.is_directory rootpath)
           then Unix.mkdir rootpath 0o755
         in
         let%lwt () =
           Lwt_io.with_file ~mode:Lwt_io.Output filepath (fun oc ->
             Lwt_io.write oc content)
         in
         Lwt.return Upload_Ok)
  in
  let rec receive_files () =
    match%lwt Dream.upload request with
    | None -> Dream.empty `Created
    | Some (Some "files", filename, _) ->
      let rec stream_file content size =
        if size > file_size_limit
        then Lwt.return Upload_Too_Large
        else (
          match%lwt Dream.upload_part request with
          | None -> try_save_file filename content
          | Some chunk -> stream_file (content ^ chunk) (size + String.length chunk))
      in
      let%lwt ret = stream_file "" 0 in
      (match ret with
       | Upload_Ok -> receive_files ()
       | Upload_Too_Large ->
         Utils.Error.send_error ~status:`Payload_Too_Large "File too large"
       | Upload_Forbidden -> Utils.Error.send_error ~status:`Forbidden "Access Forbidden"
       | Upload_Invalid_Filename ->
         Utils.Error.send_error ~status:`Bad_Request "Invalid filename")
    | Some _ ->
      let rec drain_upload () =
        match%lwt Dream.upload_part request with
        | None -> receive_files ()
        | Some _ -> drain_upload ()
      in
      drain_upload ()
  in
  receive_files ()
;;
