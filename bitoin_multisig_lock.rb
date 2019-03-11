# This contract needs 1 signed arguments:
# 0. pubkeys, used to identify token owners, separated by `,`
# 1. M, the threshold of signatures required for validation
# This contracts also accepts 2 required unsigned arguments and 1
# optional unsigned argument:
# 2. signatures, used to present ownership, separated by `,`
# 3. type, SIGHASH type
# 4. output(s), this is only used for SIGHASH_SINGLE and SIGHASH_MULTIPLE types,
# for SIGHASH_SINGLE, it stores an integer denoting the index of output to be
# signed; for SIGHASH_MULTIPLE, it stores a string of `,` separated array denoting
# outputs to sign
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


tx = CKB.load_tx
sha3 = Sha3.new

sha3.update(ARGV[3])
sighash_type = ARGV[3].to_i

if sighash_type & SIGHASH_ANYONECANPAY != 0
  # Only hash current input
  out_point = CKB.load_input_out_point(0, CKB::Source::CURRENT)
  sha3.update(out_point["hash"])
  sha3.update(out_point["index"].to_s)
  sha3.update(CKB::CellField.new(CKB::Source::CURRENT, 0, CKB::CellField::LOCK_HASH).readall)
else
  # Hash all inputs
  tx["inputs"].each_with_index do |input, i|
    sha3.update(input["hash"])
    sha3.update(input["index"].to_s)
    sha3.update(CKB.load_script_hash(i, CKB::Source::INPUT, CKB::Category::LOCK))
  end
end

case sighash_type & (~SIGHASH_ANYONECANPAY)
when SIGHASH_ALL
  tx["outputs"].each_with_index do |output, i|
    sha3.update(output["capacity"].to_s)
    sha3.update(output["lock"])
    if hash = CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::Category::TYPE)
      sha3.update(hash)
    end
  end
when SIGHASH_SINGLE
  raise "Not enough arguments" unless ARGV[4]
  output_index = ARGV[4].to_i
  output = tx["outputs"][output_index]
  sha3.update(output["capacity"].to_s)
  sha3.update(output["lock"])
  if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::Category::TYPE)
    sha3.update(hash)
  end
when SIGHASH_MULTIPLE
  raise "Not enough arguments" unless ARGV[4]
  ARGV[4].split(",").each do |output_index|
    output_index = output_index.to_i
    output = tx["outputs"][output_index]
    sha3.update(output["capacity"].to_s)
    sha3.update(output["lock"])
    if hash = CKB.load_script_hash(output_index, CKB::Source::OUTPUT, CKB::Category::TYPE)
      sha3.update(hash)
    end
  end
end
hash = sha3.final

pubkeys = ARGV[0]
pubkeys = pubkeys.split(",").map{|pubkey| hex_to_bin(pubkey) }
threshold = ARGV[1]
signatures = ARGV[2]
signatures = signatures.split(",").map{|signature| hex_to_bin(signature) }
valid_sig_count = 0

if threshold > pubkeys.length
  raise "Wrong argument of M!"
end

if threshold > signatures.length
  raise "Not enough signatures!"
end

# TODO: add signature index of the matched pubkey
signatures.each do |signature|
  # bad performance
  pubkey = pubkeys.find { |pubkey| Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash) }
  if pubkey
    pubkeys.delete_if{|i| i == pubkey }
  else
    raise "Including invalid signature!"
  end
end
