# This contract needs 3 arguments:
# 0. pubkey, used to identify token owner
# 1. signature, signature used to present ownership
# 2. string of `,` separated array denoting outputs to sign.
# It's up to transaction assembler to arrange outputs, this script
# only cares that correct data are signed.
if ARGV.length != 3
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
ARGV[2].split(",").each do |output_index|
  output_index = output_index.to_i
  output = tx["outputs"][output_index]
  blake2b.update(output["capacity"].to_s)
  blake2b.update(CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::HashType::LOCK))
  if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::HashType::TYPE)
    blake2b.update(hash)
  end
end

hash = blake2b.final

pubkey = ARGV[0]
signature = ARGV[1]

unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
  raise "Signature verification error!"
end
