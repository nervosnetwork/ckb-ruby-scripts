# This contract needs 2 required arguments:
# 0. token name, this is here so we can have different lock hash for
# different token for ease of querying. In the actual contract this is
# not used.
# 1. pubkey, used to identify token owner
# This contracts also 3 optional arguments:
# 2. signature, signature used to present ownership
# 3. type, SIGHASH type
# 4. output(s), this is only used for SIGHASH_SINGLE and SIGHASH_MULTIPLE types,
# for SIGHASH_SINGLE, it stores an integer denoting the index of output to be
# signed; for SIGHASH_MULTIPLE, it stores a string of `,` separated array denoting
# outputs to sign.
# If they exist, we will do the proper signature verification way, if not
# we will check for lock hash, and only accept transactions that have more
# tokens in the output cell than input cell so as to allow receiving tokens.
if ARGV.length != 2 && ARGV.length != 4 && ARGV.length != 5
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

if ARGV.length >= 4
  blake2b.update(ARGV[3])
  sighash_type = ARGV[3].to_i

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
    raise "Not enough arguments" unless ARGV[4]
    output_index = ARGV[4].to_i
    if output = tx["outputs"][output_index]
      blake2b_single_output(blake2b, output, output_index)
    else
      raise OUTPUT_INDEX_ERR
    end
  when SIGHASH_MULTIPLE
    raise "Not enough arguments" unless ARGV[4]
    ARGV[4].split(",").each do |output_index|
      output_index = output_index.to_i
      if output = tx["outputs"][output_index]
        blake2b_single_output(blake2b, output, output_index)
      else
        raise OUTPUT_INDEX_ERR
      end
    end
  end
  hash = blake2b.final

  pubkey = ARGV[1]
  signature = ARGV[2]

  unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
    raise "Signature verification error!"
  end
else
  # In case a signature is missing, we will only accept the tx when:
  # * The tx only has one input matching current lock hash and contract hash
  # * The tx only has one output matching current lock hash and contract hash
  # * The matched output has the same amount of capacity but more tokens
  # than the input
  # This would allow a sender to send tokens to a receiver in one step
  # without needing work from the receiver side.
  current_lock_hash = CKB.load_script_hash(0, CKB::Source::CURRENT, CKB::HashType::LOCK)
  current_contract_hash = CKB.load_script_hash(0, CKB::Source::CURRENT, CKB::HashType::TYPE)
  unless current_contract_hash
    raise "Contract is not available in current cell!"
  end
  input_matches = tx["inputs"].length.times.select do |i|
    CKB.load_script_hash(i, CKB::Source::INPUT, CKB::HashType::LOCK) == current_lock_hash &&
      CKB.load_script_hash(i, CKB::Source::INPUT, CKB::HashType::TYPE) == current_contract_hash
  end
  if input_matches.length != 1
    raise "Invalid input cell number!"
  end
  output_matches = tx["outputs"].length.times.select do |i|
    CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::HashType::LOCK) == current_lock_hash &&
      CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::HashType::TYPE) == current_contract_hash
  end
  if output_matches.length != 1
    raise "Invalid output cell number!"
  end
  input_index = input_matches[0]
  output_index = output_matches[0]
  input_capacity = CKB::CellField.new(CKB::Source::INPUT, input_index, CKB::CellField::CAPACITY).read(0, 8).unpack("Q<")[0]
  output_capacity = CKB::CellField.new(CKB::Source::OUTPUT, output_index, CKB::CellField::CAPACITY).read(0, 8).unpack("Q<")[0]
  if input_capacity != output_capacity
    raise "Capacity cannot be tweaked!"
  end
  input_amount = CKB::CellField.new(CKB::Source::INPUT, input_index, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
  output_amount = CKB::CellField.new(CKB::Source::OUTPUT, output_index, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
  if output_amount <= input_amount
    raise "You can only deposit tokens here!"
  end
end
