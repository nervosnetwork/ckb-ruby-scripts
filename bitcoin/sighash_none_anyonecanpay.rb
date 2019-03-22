# This contract needs 2 arguments:
# 0. pubkey, used to identify token owner
# 1. signature, signature used to present ownership
if ARGV.length != 2
  raise "Wrong number of arguments!"
end

def hex_to_bin(s)
  if s.start_with?("0x")
    s = s[2..-1]
  end
  [s].pack("H*")
end

tx = CKB.load_tx
blake2b = Blake2b.new

out_point = CKB.load_input_out_point(0, CKB::Source::CURRENT)
blake2b.update(out_point["hash"])
blake2b.update(out_point["index"].to_s)
hash = blake2b.final

pubkey = ARGV[0]
signature = ARGV[1]

unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
  raise "Signature verification error!"
end
