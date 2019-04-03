# This contract needs 4 required arguments:
# 0. token name, this is here so we can have different lock hash for
# different token for ease of querying. In the actual contract this is
# not used.
# 1. type, SIGHASH type
# One optional argument might be needed here:
# 2. output(s), this is only used for SIGHASH_SINGLE and SIGHASH_MULTIPLE types,
# for SIGHASH_SINGLE, it stores an integer denoting the index of output to be
# signed; for SIGHASH_MULTIPLE, it stores a string of `,` separated array denoting
# outputs to sign
#
# This contract needs 2 witnesses:
# 3. pubkey, used to identify token owner
# 4. signature, signature used to present ownership
if ARGV.length != 4 && ARGV.length != 5
  raise "Wrong number of arguments!"
end

SIGHASH_ALL = 0x1
SIGHASH_NONE = 0x2
SIGHASH_SINGLE = 0x3
SIGHASH_MULTIPLE = 0x4
SIGHASH_ANYONECANPAY = 0x80

def hex_to_bin(s)
  if s.start_with?("0x")
    s = s[2..-1]
  end
  [s].pack("H*")
end

def blake2b_single_output(blake2b, output, output_index)
  blake2b.update(output["capacity"].to_s)
  blake2b.update(CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::HashType::LOCK))
  if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::HashType::TYPE)
    blake2b.update(hash)
  end
end

OUTPUT_INDEX_ERR = "Output index error!".freeze

tx = CKB.load_tx
blake2b = Blake2b.new

blake2b.update(ARGV[1])
sighash_type = ARGV[1].to_i

if sighash_type & SIGHASH_ANYONECANPAY != 0
  # Only hash current input
  out_point = CKB.load_input_out_point(0, CKB::Source::CURRENT)
  blake2b.update(out_point["hash"])
  blake2b.update(out_point["index"].to_s)
else
  # Hash all inputs
  tx["inputs"].each_with_index do |input, i|
    blake2b.update(input["hash"])
    blake2b.update(input["index"].to_s)
  end
end

case sighash_type & (~SIGHASH_ANYONECANPAY)
when SIGHASH_ALL
  tx["outputs"].each_with_index do |output, i|
    blake2b_single_output(blake2b, output, i)
  end
when SIGHASH_SINGLE
  raise "Not enough arguments" unless ARGV[2]
  output_index = ARGV[2].to_i
  if output = tx["outputs"][output_index]
    blake2b_single_output(blake2b, output, output_index)
  else
    raise OUTPUT_INDEX_ERR
  end
when SIGHASH_MULTIPLE
  raise "Not enough arguments" unless ARGV[2]
  ARGV[2].split(",").each do |output_index|
    output_index = output_index.to_i
    if output = tx["outputs"][output_index]
      blake2b_single_output(blake2b, output, output_index)
    else
      raise OUTPUT_INDEX_ERR
    end
  end
end
hash = blake2b.final

pubkey = ARGV[-2]
signature = ARGV[-1]

unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
  raise "Signature verification error!"
end
