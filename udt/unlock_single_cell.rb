# This contract needs 2 required arguments:
# 0. token name, this is here so we can have different lock hash for
# different token for ease of querying. In the actual contract this is
# not used.
# 1. pubkey hash, used to identify token owner
# This contracts also can accept 2 optional arguments:
# 2. pubkey, used to identify token owner
# 3. signature, signature used to present ownership
# If they exist, we will do the proper signature verification way, if not
# we will check for lock hash, and only accept transactions that have more
# tokens in the output cell than input cell so as to allow receiving tokens.
if ARGV.length != 2 && ARGV.length != 4
  raise "Wrong number of arguments!"
end

if ARGV.length == 4
  public_key_hash = [ARGV[1][2..-1]].pack("H*")
  public_key = [ARGV[2][2..-1]].pack("H*")
  signature = [ARGV[3][2..-1]].pack("H*")

  hash = Blake2b.new.update(pubkey).final[0..20]
  unless hash == pubkey_hash
    raise "Invalid pubkey!"
  end

  message = CKB.load_tx_hash

  unless Secp256k1.verify(public_key, signature, message)
    raise "Signature verification error!"
  end
end

# In case a signature is missing, we will only accept the tx when:
# * The tx only has one input matching current lock hash and contract hash
# * The tx only has one output matching current lock hash and contract hash
# * The matched output has the same amount of capacity but more tokens
# than the input
# This would allow a sender to send tokens to a receiver in one step
# without needing work from the receiver side.
current_lock_hash = CKB.load_script_hash
# Locate current cell first
current_cell_index = nil
i = 0
loop do
  hash = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::LOCK_HASH).readall
  if hash == current_lock_hash
    raise "More than one target cell exists!" if current_cell_index
    current_cell_index = i
  end
  i += 1
rescue CKB::IndexOutOfBound
  break
end
raise "Target input cell does not exist!" unless current_cell_index

current_type_hash = CKB::CellField.new(CKB::Source::INPUT, current_cell_index,
                                  CKB::CellField::TYPE_HASH).readall
raise "Type hash does not exist" unless current_type_hash

input_index = nil
i = 0
loop do
  lock = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::LOCK_HASH)
  type = CKB::CellField.new(CKB::Source::INPUT, i, CKB::CellField::TYPE_HASH)
  if current_lock_hash == lock && current_type_hash == type
    raise "Multiple input cell exists!" if input_index
    input_index = i
  end
  i += 1
rescue CKB::IndexOutOfBound
  break
end
output_index = nil
i = 0
loop do
  lock = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::LOCK_HASH)
  type = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::TYPE_HASH)
  if current_lock_hash == lock && current_type_hash == type
    raise "Multiple output cell exists!" if output_index
    output_index = i
  end
  i += 1
rescue CKB::IndexOutOfBound
  break
end

input_capacity = CKB::CellField.new(CKB::Source::INPUT, input_index, CKB::CellField::CAPACITY).read(0, 8).unpack("Q<")[0]
output_capacity = CKB::CellField.new(CKB::Source::OUTPUT, output_index, CKB::CellField::CAPACITY).read(0, 8).unpack("Q<")[0]
if input_capacity != output_capacity
  raise "Capacity cannot be tweaked!"
end
input_amount = CKB::CellField.new(CKB::Source::INPUT, input_index, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
if CKB::CellField.new(CKB::Source::OUTPUT, output_index, CKB::CellField::DATA).length > 8
  raise "Too much data is used!"
end
output_amount = CKB::CellField.new(CKB::Source::OUTPUT, output_index, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]
if output_amount <= input_amount
  raise "You can only deposit tokens here!"
end
