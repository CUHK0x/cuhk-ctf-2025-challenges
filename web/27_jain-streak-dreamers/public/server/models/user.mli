module type DB = Caqti_lwt.CONNECTION

type t =
  { id : int
  ; username : string
  ; password : string
  }
[@@deriving yojson]

val create : Doc.User_create_doc.t -> (module DB) -> t Lwt.t
val read : Doc.User_read_doc.t -> (module DB) -> t option Lwt.t
