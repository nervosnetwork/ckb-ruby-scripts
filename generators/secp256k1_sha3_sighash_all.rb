if ARGV.length < 1
  raise "Not enough arguments!"
end

tx = CKB.load_tx
blake2b = Blake2b.new

blake2b.update(tx["version"].to_s)
tx["deps"].each do |dep|
  blake2b.update(dep["hash"])
  blake2b.update(dep["index"].to_s)
end
tx["inputs"].each do |input|
  blake2b.update(input["hash"])
  blake2b.update(input["index"].to_s)
  blake2b.update(input["unlock"]["version"].to_s)
  # First argument here is signature
  input["unlock"]["arguments"].drop(1).each do |argument|
    blake2b.update(argument)
  end
end
tx["outputs"].each do |output|
  blake2b.update(output["capacity"].to_s)
  blake2b.update(output["lock"])
end
hash = blake2b.final

def hex_to_bin(s)
  [s].pack("H*")
end

def bin_to_hex(s)
  s.unpack("H*")[0]
end

seckey = hex_to_bin(ARGV[0])
pubkey = Secp256k1.pubkey(seckey)
CKB.debug "Pubkey: #{bin_to_hex(pubkey)}"

signature = Secp256k1.sign(seckey, hash)
CKB.debug "Signature: #{bin_to_hex(signature)}"
