open Ppx_yojson_conv_lib.Yojson_conv.Primitives

type t = { filenames : string list } [@@deriving yojson]
