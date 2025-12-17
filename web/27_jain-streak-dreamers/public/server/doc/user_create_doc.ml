open Ppx_yojson_conv_lib.Yojson_conv.Primitives

type t =
  { username : string
  ; password : string
  }
[@@deriving yojson]
