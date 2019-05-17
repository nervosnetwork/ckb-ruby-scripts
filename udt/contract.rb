# This contract needs 2 arguments:
# 0. token name, this is just a placeholder to distinguish between tokens,
# it will not be used in the actual contract. The pair of token name and
# pubkey uniquely identifies a token.
# 1. pubkey hash, used to perform supermode operations such as issuing new tokens
if ARGV.length != 2
  raise "Not enough arguments!"
end

current_hash = CKB.load_script_hash

outputs = []
supermode_data = nil

i = 0
loop do
  hash = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::TYPE_HASH).readall
  next if current_hash == hash
  data = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::DATA).readall
  outputs << data[0, 8].unpack("Q<")[0]
  if data.length > 8
    if supermode_data
      raise "Cannot have more than one supermode output cell!"
    end

    witness_index = data[8, 8].unpack("Q<")[0]
    witness = CKB.parse_witness(CKB.load_witness(witness_index))["data"]
    supermode_data = {
      pubkey: witness[witness.length - 2],
      signature: witness[witness.length - 1]
    }
  end
  data.clear
  i += 1
rescue CKB::IndexOutOfBound
  break
end

# There are 2 ways to execute this contract:
# * Normal user can run the contract with only contract hash attached
# as an argument, this will ensure the contract to run sum verification
# * For superuser denoted via the pubkey from signed_args, they can
# also do more operations such as issuing more tokens. They can change
# the script to a special mode by attaching a signature signed from private
# key for the pubkey attached. With this signature, they will be able to
# add more tokens.
if supermode_data
  # Validate pubkey
  hash = Blake2b.new.update(supermode_data[:pubkey]).final[0..20]
  if hash != [ARGV[1][2..-1]].pack("H*")
    raise "Invalid pubkey!"
  end

  # Validate signature
  message = CKB.load_tx_hash
  unless Secp256k1.verify(supermode_data[:pubkey], supermode_data[:signature], message)
    raise "Signature verification error!"
  end
  return
end

inputs = []

i = 0
loop do
  hash = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::TYPE_HASH).readall
  next if current_hash == hash
  data = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::DATA).readall
  inputs << data[0, 8].unpack("Q<")[0]
  i += 1
rescue CKB::IndexOutOfBound
  break
end

if inputs.reduce(&:+) != outputs.reduce(&:+)
  raise "Sum verification failed!"
end
