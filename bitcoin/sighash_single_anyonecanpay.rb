# This contract needs 1 signed arguments:
# 1. pubkey, used to identify token owner
# This contracts also accepts one unsigned argument:
# 2. signature, signature used to present ownership
# 3. index, an integer denoting the index of output to be signed.
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

OUTPUT_INDEX_ERR = "Output index error!".freeze

tx = CKB.load_tx
blake2b = Blake2b.new

out_point = CKB.load_input_out_point(0, CKB::Source::CURRENT)
blake2b.update(out_point["hash"])
blake2b.update(out_point["index"].to_s)
blake2b.update(CKB::CellField.new(CKB::Source::CURRENT, 0, CKB::CellField::LOCK_HASH).readall)
output_index = ARGV[2].to_i
if output = tx["outputs"][output_index]
  blake2b.update(output["capacity"].to_s)
  blake2b.update(output["lock"])
  if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::Category::TYPE)
    blake2b.update(hash)
  end
else
  raise OUTPUT_INDEX_ERR
end

hash = blake2b.final

pubkey = ARGV[0]
signature = ARGV[1]

unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
  raise "Signature verification error!"
end
