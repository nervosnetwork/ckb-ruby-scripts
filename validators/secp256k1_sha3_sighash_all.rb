if ARGV.length < 2
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

pubkey = ARGV[0]
signature = ARGV[1]

def hex_to_bin(s)
  [s].pack("H*")
end

unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
  raise "Signature verification error!"
end
