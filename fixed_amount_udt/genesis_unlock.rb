# This contract needs following required arguments:
# 0. input hash, used to uniquely identify current cell
# 1. rate, used to tell how many tokens can 1 CKB capacity exchange.
# 2. lock hash, used to receive capacity in ICO phase
# 3. pubkey hash, used to identify token owner
#
# This contracts also 2 optional arguments:
# 4. public key, signature used to present ownership
# 5. signature, signature used to present ownership
# If they exist, we will do the proper signature verification way, if not
# we will check and perform an ICO step using rate.
if ARGV.length != 4 && ARGV.length != 6
  raise "Wrong number of arguments!"
end

if ARGV.length == 6
  public_key_hash = [ARGV[3][2..-1]].pack("H*")
  public_key = [ARGV[4][2..-1]].pack("H*")
  signature = [ARGV[5][2..-1]].pack("H*")

  hash = Blake2b.new.update(pubkey).final[0..20]
  unless hash == pubkey_hash
    raise "Invalid pubkey!"
  end

  message = CKB.load_tx_hash

  unless Secp256k1.verify(public_key, signature, message)
    raise "Signature verification error!"
  end
  return
end

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
current_input_capacity = CKB::CellField.new(CKB::Source::INPUT,
                                       current_cell_index,
                                       CKB::CellField::CAPACITY).readall.unpack("Q<")[0]
current_input_tokens = CKB::CellField.new(CKB::Source::INPUT,
                                     current_cell_index,
                                     CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]

# First we test that there's one output cell transformed from current cell.
current_output_index = nil
i = 0
loop do
  lock = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::LOCK_HASH)
  type = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::TYPE_HASH)
  capacity = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::CAPACITY).readall.unpack("Q<")[0]

  if lock = current_lock_hash && type == current_type_hash && capacity == current_input_capacity
    current_output_index = i
    break
  end
  i += 1
rescue CKB::IndexOutOfBound
  break
end
unless current_output_index
  raise "Cannot find corresponding output cell for current input!"
end
if CKB::CellField.new(CKB::Source::OUTPUT, current_output_index, CKB::CellField::DATA).length != 8
  raise "Invalid UDT output cell data length!"
end
output_tokens = CKB::CellField.new(CKB::Source::OUTPUT, current_output_index, CKB::CellField::DATA).read(0, 8).unpack("Q<")[0]

# Finally, we test that in exchange for tokens, the sender has paid enough capacity
# in a new empty cell.
target_lock_hash = [ARGV[2][2..-1]].pack("H*")
paid_output_index = nil
i = 0
loop do
  lock = CKB::CellField.new(CKB::Source::OUTPUT, i, CKB::CellField::LOCK_HASH)
  if lock == target_lock_hash
    paid_output_index = i
    break
  end
  i += 1
rescue CKB::IndexOutOfBound
  break
end
unless paid_output_index
  raise "Cannot find paid output!"
end
if CKB::CellField.new(CKB::Source::OUTPUT, paid_output_index, CKB::CellField::DATA).length > 0
  raise "Not an empty cell!"
end
if CKB::CellField.new(CKB::Source::OUTPUT, paid_output_index, CKB::CellField::TYPE).exists?
  raise "Not an empty cell!"
end
rate = ARGV[1].to_i
required_capacity = (current_input_tokens - output_tokens + rate - 1) / rate
paid_capacity = CKB::CellField.new(CKB::Source::OUTPUT, paid_output_index, CKB::CellField::CAPACITY).readall.unpack("Q<")[0]
if paid_capacity != required_capacity
  raise "Paid capacity is wrong!"
end
