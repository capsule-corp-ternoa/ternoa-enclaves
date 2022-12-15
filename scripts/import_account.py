from substrateinterface import Keypair,utils
import getpass
import json
import sys
import base58
 

if len(sys.argv) < 2 :
    print('Please specify the exported json file of ternoa account.')
    exit

with open(sys.argv[1]) as json_file:
    data = json.load(json_file)
    #print(data)

password = getpass.getpass('Please enter password for your exported Ternoa Account :')


#keypair = Keypair.create_from_encrypted_json(json_data, password, ss58_format=42)

private_key, public_key = utils.encrypted_json.decode_pair_from_encrypted_json(data, password)

print(private_key.hex()+"_"+public_key.hex())
