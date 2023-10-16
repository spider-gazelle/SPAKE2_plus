require "./algorithms"
require "openssl/hmac"
require "hkdf"
require "big"

class SPAKE2Plus::Protocol
  def initialize(
    @algorithm : Algorithms,
    context : String | Bytes,
    @random : BigInt,
    @w0 : BigInt,
    @id_prover : String = "",
    @id_verifier : String = ""
  )
    @context = context.to_slice
  end

  getter algorithm : Algorithms
  getter context : Bytes
  getter random : BigInt
  getter w0 : BigInt
  getter id_prover : String
  getter id_verifier : String

  getter compute_x : Bytes do
    x = algorithm.generator_point.mul(random)
    x = x.add(algorithm.m.mul(w0))
    x.to_slice
  end

  getter compute_y : Bytes do
    y = algorithm.generator_point.mul(random)
    y = y.add(algorithm.n.mul(w0))
    y.to_slice
  end

  def compute_secret_and_verifiers_from_y(w1 : BigInt, x : Bytes, y : Bytes)
    y_point = algorithm.curve_group.point.at_position(y)
    raise "Y is not on the curve" unless y_point.valid?
    y_neg_wo = y_point.add(algorithm.n.mul(w0).negate)
    z = y_neg_wo.mul(random)
    v = y_neg_wo.mul(w1)

    compute_secret_and_verifiers(x, y, z.to_slice, v.to_slice)
  end

  def compute_secret_and_verifiers_from_x(l : Bytes, x : Bytes, y : Bytes)
    l_point = algorithm.curve_group.point.at_position(l)
    x_point = algorithm.curve_group.point.at_position(x)
    raise "X is not on the curve" unless x_point.valid?
    z = x_point.add(algorithm.m.mul(w0).negate).mul(random)
    v = l_point.mul(random)

    compute_secret_and_verifiers(x, y, z.to_slice, v.to_slice)
  end

  protected def compute_secret_and_verifiers(x : Bytes, y : Bytes, z : Bytes, v : Bytes)
    hash = compute_transcript_hash(x, y, z, v)
    k_size = hash.size // 2
    ka = hash[0...k_size]
    ke = hash[k_size...hash.size]

    # TODO:: not sure if we should be using hash.size == 32 / k_size == 16 here
    kc_ab = HKDF.derive_key(Bytes[0], ka, "ConfirmationKeys".to_slice, hash.size, algorithm.hash_algorithm)
    kc_a = kc_ab[0...k_size]
    kc_b = kc_ab[k_size...hash.size]

    h_ay = algorithm.mac(kc_a, y)
    h_bx = algorithm.mac(kc_b, x)

    {ke, h_ay, h_bx}
  end

  protected def compute_transcript_hash(share_p : Bytes, share_v : Bytes, z : Bytes, v : Bytes)
    io = IO::Memory.new
    add_to_context io, context
    add_to_context io, @id_prover
    add_to_context io, @id_verifier
    add_to_context io, algorithm.m
    add_to_context io, algorithm.n
    add_to_context io, share_p
    add_to_context io, share_v
    add_to_context io, z
    add_to_context io, v
    # ensure we have valid hex for the conversion
    hex = w0.to_s(16)
    add_to_context(io, hex.size.even? ? hex.hexbytes : "0#{hex}".hexbytes)

    algorithm.hash(io)
  end

  protected def add_to_context(io : IO::Memory, data)
    bytes = data.to_slice
    io.write_bytes(bytes.size.to_u64, IO::ByteFormat::LittleEndian)
    io.write bytes
  end
end
