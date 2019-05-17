# This contract needs following arguments:
# 0. hash of all inputs in bootstrap tx. By including this field here, different
# bootstrapping phases would generate contracts with different type hash, hence
# preventing the problem when token creator executes more than one token creation
# process, ensuring that we can create a token with a fixed upper limit.
# 1. pubkey hash, used to identify token owner
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

if supermode_data
  # Validate input outpoint hash
  b = Blake2b.new
  i = 0
  loop do
    b.update(CKB::InputField.new(CKB::Source::INPUT, i,
                                 CKB::InputField::OUT_POINT).readall)
    i += 1
  rescue CKB::IndexOutOfBound
    break
  end
  if b.final != [ARGV[0][2..-1]].pack("H*")
    raise "Invalid input outpoint hash!"
  end

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
