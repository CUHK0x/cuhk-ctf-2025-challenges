module type DB = Caqti_lwt.CONNECTION

type t =
  { timestamp : int
  ; content : string
  }
[@@deriving yojson]

val create : Doc.Thing_create_doc.t -> (module DB) -> t Lwt.t
val read_all : (module DB) -> t list Lwt.t
