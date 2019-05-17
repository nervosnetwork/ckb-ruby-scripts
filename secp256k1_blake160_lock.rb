if ARGV.length != 3
  raise "Wrong number of arguments!"
end

public_key_hash = [ARGV[0][2..-1]].pack("H*")
public_key = [ARGV[1][2..-1]].pack("H*")
signature = [ARGV[2][2..-1]].pack("H*")

hash = Blake2b.new.update(pubkey).final[0..20]
unless hash == pubkey_hash
  raise "Invalid pubkey!"
end

message = CKB.load_tx_hash

unless Secp256k1.verify(public_key, signature, message)
  raise "Signature verification error!"
end
