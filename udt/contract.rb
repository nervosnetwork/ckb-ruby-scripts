# This contract needs 2 arguments:
# 0. token name, this is just a placeholder to distinguish between tokens,
# it will not be used in the actual contract. The pair of token name and
# pubkey uniquely identifies a token.
# 1. pubkey, used to perform supermode operations such as issuing new tokens
if ARGV.length != 2
  raise "Not enough arguments!"
end

def hex_to_bin(s)
  if s.start_with?("0x")
    s = s[2..-1]
  end
  [s].pack("H*")
end

current_hash = CKB.load_script_hash(0, CKB::Source::CURRENT, CKB::HashType::TYPE)

tx = CKB.load_tx

cell = CKB::CellField.new(CKB::Source::CURRENT, 0, CKB::CellField::DATA)
cell_data_length = cell.length
supermode = false
# There are 2 ways to execute this contract:
# * Normal user can run the contract with only contract hash attached
# as an argument, this will ensure the contract to run sum verification
# * For superuser denoted via the pubkey from signed_args, they can
# also do more operations such as issuing more tokens. They can change
# the script to a special mode by attaching a signature signed from private
# key for the pubkey attached. With this signature, they will be able to
# add more tokens.
if cell_data_length > 8
  signature = cell.read(8, cell_data_length - 8)

  blake2b = Blake2b.new
  tx["inputs"].each_with_index do |input, i|
    if CKB.load_script_hash(i, CKB::Source::INPUT, CKB::HashType::TYPE) == current_hash
      blake2b.update(CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 8))
    end
  end
  tx["outputs"].each_with_index do |output, i|
    if CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::HashType::TYPE) == current_hash
      blake2b.update(CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::DATA).read(0, 8))
    end
  end

  data = blake2b.final

  unless Secp256k1.verify(hex_to_bin(ARGV[1]), signature, data)
    raise "Signature verification error!"
  end
  supermode = true
end

input_sum = tx["inputs"].size.times.map do |i|
  if CKB.load_script_hash(i, CKB::Source::INPUT, CKB::HashType::TYPE) == current_hash
    CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
  else
    0
  end
end.reduce(&:+)

output_sum = tx["outputs"].size.times.map do |i|
  if CKB.load_script_hash(i, CKB::Source::OUTPUT, CKB::HashType::TYPE) == current_hash
    CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
  else
    0
  end
end.reduce(&:+)

# This contract here allows destroying tokens, a different contract might
# choose to forbid this.
if (!supermode) && input_sum < output_sum
  raise "Sum verification failed!"
end
