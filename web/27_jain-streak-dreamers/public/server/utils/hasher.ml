let t_cost = 2
and m_cost = 65536
and parallelism = 1
and hash_len = 32
and salt_len = 10

let encoded_len =
  Argon2.encoded_len ~t_cost ~m_cost ~parallelism ~salt_len ~hash_len ~kind:ID
;;

let gen_salt len = Dream.random len

let hash passwd =
  match
    Argon2.hash
      ~t_cost
      ~m_cost
      ~parallelism
      ~hash_len
      ~encoded_len
      ~pwd:passwd
      ~salt:(gen_salt salt_len)
      ~kind:ID
      ~version:Argon2.VERSION_NUMBER
  with
  | Ok (_, encoded) -> encoded
  | Error e -> raise (Failure (Argon2.ErrorCodes.message e))
;;

let verify encoded pwd =
  match Argon2.verify ~encoded ~pwd ~kind:ID with
  | Ok true_or_false -> true_or_false
  | Error VERIFY_MISMATCH -> false
  | Error e -> raise (Failure (Argon2.ErrorCodes.message e))
;;
