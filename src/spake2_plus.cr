require "openssl_ext"
require "ed25519"
require "hkdf"
require "cmac"

# Password Authenticated Key Exchange (PAKE)
# https://datatracker.ietf.org/doc/pdf/draft-bar-cfrg-spake2plus-02.pdf
module SPAKE2Plus
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  enum Curve
    P256
    P384
    P521
    Edwards25519
  end

  enum MAC
    HMAC
    CMAC # CMAC-AES-128
  end

  MATTER_DEFAULT = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::HMAC)

  def self.new(context : String | Bytes, w0 : BigInt, algorithm : Algorithms = MATTER_DEFAULT) : SPAKE2Plus::Protocol
    random = Random.new.rand(BigInt.new...curve.prime_modulus.to_big_i)
    Protocol.new(algorithm, context, random, w0)
  end
end

require "./spake2_plus/algorithms"
require "./spake2_plus/protocol"
