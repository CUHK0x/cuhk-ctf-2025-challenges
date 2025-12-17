open Ppx_yojson_conv_lib.Yojson_conv.Primitives

type t =
  { version : int
  ; description : string
  }
[@@deriving yojson]
