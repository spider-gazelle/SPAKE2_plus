require "cmac"
require "openssl_ext"
require "digest/sha256"
require "digest/sha512"

class SPAKE2Plus::Algorithms
  GRAPH = {
    Curve::P256 => {
      name:      "P-256",
      hash:      [OpenSSL::Algorithm::SHA256, OpenSSL::Algorithm::SHA512],
      m:         "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
      n:         "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49",
      ws_length: (256 // 8) + 8,
    },
    Curve::P384 => {
      name:      "P-384",
      hash:      [OpenSSL::Algorithm::SHA256, OpenSSL::Algorithm::SHA512],
      m:         "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853",
      n:         "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10",
      ws_length: (384 // 8) + 8,
    },
    Curve::P521 => {
      name:      "P-521",
      hash:      [OpenSSL::Algorithm::SHA512],
      m:         "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa",
      n:         "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25",
      ws_length: (521 // 8) + 8,
    },
    Curve::Edwards25519 => {
      name:      "edwards25519",
      hash:      [OpenSSL::Algorithm::SHA256],
      m:         "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf",
      n:         "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab",
      ws_length: (255 // 8) + 8,
    },
    # No support currently for edwards448
    # m: b6221038a775ecd007a4e4dde39fd76ae91d3cf0cc92be8f0c2fa6d6b66f9a12942f5a92646109152292464f3e63d354701c7848d9fc3b8880
    # n: 6034c65b66e4cd7a49b0edec3e3c9ccc4588afd8cf324e29f0a84a072531c4dbf97ff9af195ed714a689251f08f8e06e2d1f24a0ffc0146600
  }

  def initialize(@curve_name : Curve, hash_algorithm : OpenSSL::Algorithm? = nil, @mac_algorithm : MAC = MAC::HMAC)
    raise "invalid curve and MAC combination" if @mac_algorithm.cmac? && @curve_name != Curve::P256
    valid = GRAPH[@curve_name]
    @hash_algorithm = hash_algorithm || valid[:hash].first
    raise "invalid curve and hash algorithm combination" unless valid[:hash].includes?(@hash_algorithm)
    @ws_length = valid[:ws_length]
    @m = curve_group.point.at_position valid[:m].hexbytes
    @n = curve_group.point.at_position valid[:n].hexbytes
  end

  getter curve_name : Curve
  getter hash_algorithm : OpenSSL::Algorithm
  getter mac_algorithm : MAC
  getter m : OpenSSL::PKey::EC::Point
  getter n : OpenSSL::PKey::EC::Point
  getter ws_length : Int32

  getter curve : OpenSSL::PKey::EC do
    name = GRAPH[curve_name][:name]
    case curve_name
    in Curve::P256, Curve::P384, Curve::P521
      OpenSSL::PKey::EC.generate(name)
    in Curve::Edwards25519
      # TODO:: Implement
      raise NotImplementedError.new("#{name} not available yet")
    end
  end

  getter curve_group : OpenSSL::PKey::EC::Group do
    curve.group
  end

  getter generator_point : OpenSSL::PKey::EC::Point do
    curve_group.generator
  end

  def compute_w0_w1(pw : String | Bytes, salt : String | Bytes, iterations : Int) : Tuple(BigInt, BigInt)
    ws_len = ws_length
    order = curve_group.order
    ws = OpenSSL::PKCS5.pbkdf2_hmac(pw.to_slice, salt, iterations, hash_algorithm, ws_len * 2)
    w0 = OpenSSL::BN.from_bin(ws[0, ws_len]).to_big % order
    w1 = OpenSSL::BN.from_bin(ws[ws_len, ws_len]).to_big % order

    {w0, w1}
  end

  def compute_w0_l(pw : String | Bytes, salt : String | Bytes, iterations : Int) : Tuple(BigInt, Bytes)
    w0, w1 = compute_w0_w1(pw, salt, iterations)
    l = generator_point.mul(w1).to_slice
    {w0, l}
  end

  def hash(data) : Bytes
    OpenSSL::Digest.new(hash_algorithm.to_s).update(data.to_slice).final
  end

  def mac(key : Bytes, data : Bytes) : Bytes
    case mac_algorithm
    in .hmac?
      OpenSSL::HMAC.digest(hash_algorithm, key, data)
    in .cmac?
      CMAC.new(key).sign(data)
    end
  end
end
