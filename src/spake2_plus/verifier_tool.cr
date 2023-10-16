require "option_parser"
require "openssl_ext"

# # https://github.com/project-chip/connectedhomeip/blob/master/scripts/tools/spake2p/spake2p.py

# Forbidden passcodes as listed in the "5.1.7.1. Invalid Passcodes" section of the Matter spec
INVALID_PASSCODES = {
  0x000000_u32,
  11111111_u32,
  22222222_u32,
  33333333_u32,
  44444444_u32,
  55555555_u32,
  66666666_u32,
  77777777_u32,
  88888888_u32,
  99999999_u32,
  12345678_u32,
  87654321_u32,
}

def generate_verifier(passcode : UInt32, salt : Bytes, iterations : Int) : Bytes
  io = IO::Memory.new
  io.write_bytes(passcode, IO::ByteFormat::LittleEndian)

  # "prime256v1" or "secp256r1" are aliases for "P-256"
  curve = OpenSSL::PKey::EC.generate("P-256")
  group = curve.group
  point = group.generator
  ws_length = group.baselen + 8
  nist256p_order = group.order

  ws = OpenSSL::PKCS5.pbkdf2_hmac(io.to_slice, salt, iterations, OpenSSL::Algorithm::SHA256, ws_length * 2)
  w0 = OpenSSL::BN.from_bin(ws[0, ws_length]).to_big % nist256p_order
  w1 = OpenSSL::BN.from_bin(ws[ws_length, ws_length]).to_big % nist256p_order

  point = point.mul(w1)

  w0_bytes = OpenSSL::BN.new(w0).to_bin
  point_bytes = point.uncompressed_bytes

  w0_bytes + point_bytes
end

passcode = 0_u32
salt = Bytes.new(0)
iterations = 0

OptionParser.parse(ARGV.dup) do |parser|
  parser.banner = "usage: #{PROGRAM_NAME} [subcommand] [arguments]"

  parser.on("gen-verifier", "Generate SPAKE2+ Verifier") do
    parser.banner = "usage: #{PROGRAM_NAME} gen-verifier -p PASSCODE -s SALT -i count"
    parser.on("-p CODE", "--passcode=CODE", "8-digit passcode") { |p| passcode = p.to_u32 }
    parser.on("-s SALT", "--salt=SALT", "Salt of length 16 to 32 octets encoded in Base64") { |s| salt = Base64.decode(s) }
    parser.on("-i COUNT", "--iterations=COUNT", "Iteration count between 1000 and 100000") { |i| iterations = i.to_i }
  end

  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit 0
  end
end

unless 0_u32 <= passcode <= 99999999_u32
  puts "passcode out of range"
  exit 1
end

if passcode.in? INVALID_PASSCODES
  puts "invalid passcode"
  exit 2
end

unless 16 <= salt.size <= 32
  puts "invalid salt length"
  exit 3
end

unless 1000 <= iterations <= 100000
  puts "iteration count out of range"
  exit 4
end

output = generate_verifier(passcode, salt, iterations)
puts Base64.strict_encode(output)
