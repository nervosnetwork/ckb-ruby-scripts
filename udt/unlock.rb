# This contract needs 4 required arguments:
# 0. token name, this is here so we can have different lock hash for
# different token for ease of querying. In the actual contract this is
# not used.
# 1. pubkey hash, used to identify token owner
# 2. pubkey, used to identify token owner
# 3. signature, signature used to present ownership
if ARGV.length != 4
  raise "Wrong number of arguments!"
end

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
