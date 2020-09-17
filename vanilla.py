#!/usr/bin/python3

"""
    Vanilla Wallet: a multi currency cold store wallet

    Supported currencies:
        Bitcoin 
            legacy, bech32, segwith
        Ethereum
            ETH, Classic, Quadrans
        Litecoin
        Dash

    NOTE:
        This code is provided "AS IS" with all faults, defects, bugs, and errors.
        Developers, authors  and mantainers of the code makes no warranties, express
        or implied, and hereby disclaims all implied warranties, including any 
        warranty of merchantability and warranty of fitness for a particular purpose.
        Use it at your own risk. 
        Developers, authors  and mantainers cannot be held responsible for any damage 
        or loss deriving from the use of this code

    Why vanilla?
        vanilla stands for "simple & plain", also is an ingredient for iced coffe :)

    Credits:
        - Massimo S. Musumeci massmux https://github.com/massmux/bip39gen
        - MaxP

    Licence:
        GNU General Public Licence V3

    Tested against:
        https://privatekeys.pw
        https://learnmeabitcoin.com/technical/wif
        https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
        https://www.bitaddress.org/

"""


### Imports
import sys
import subprocess
import json
import re
from sty import fg, bg, ef, rs
import sounddevice as sd

import cli
import helper

import bit
from bit import utils
from mnemonic import Mnemonic
from web3 import Web3
import eth_keyfile
import bech32
import base58
# import scrypt
# from Crypto.Cipher import AES
from graphenebase import PrivateKey
from graphenebase.bip38 import encrypt

import binascii
from binascii import hexlify, unhexlify
import hashlib


### Globlals & Constants 

MIC_RND_SEC = 30        # seconds of mic sampling for private key generation
SHA_RND_RND = 2048      # number of sha256 rounds for private key generation
MIC_SLT_SEC = 5         # seconds of mic sampling for salt

Args = {}               # Parameters received from command line argiments
dataDict={}             # Dictionaries of values to share between BC address creation functions (RORO approach)

JOut={}                 # JSON Output Object

####################################################################################################
##
## KEY MANAGEMENT FUNCTIONS
##

def generatePrivateKey():
    global dataDict
    if (Args.entropy):
        # accept and use entropy string provided by user instead of mic one
        # print("You provided the entropy as a string")
        hash0=hashlib.sha256(Args.entropy.encode('utf-8')).hexdigest()
        # print("256bits hash from your source: %s" % hash0)
        salt0=""
    else:
        # create random by reading the mic for rnd_len seconds
        print("Getting entropy from %s secs mic audio recording... Please wait (and make some noise)" % str(MIC_RND_SEC) )
        hash0=helper.getNoiseFromMicrophone(MIC_RND_SEC)

        # create random for salt
        print("Getting salt from %s secs mic audio recording... Please wait (and make some noise)" % str(MIC_SLT_SEC))
        salt0=helper.getNoiseFromMicrophone(MIC_SLT_SEC)

    """ sha256 rounds """
    print ("Iterating %s rounds of salted sha256 hashing... Please wait" % SHA_RND_RND )
    for i in range(0,SHA_RND_RND):
        hash0=hashlib.sha256((hash0+salt0).encode('utf-8')).hexdigest()


    # Store raw private key
    dataDict["privateKey"] = hash0
    # Create ECDSA private key
    dataDict["bitcoinKey"] = bit.PrivateKeyTestnet.from_hex(dataDict["privateKey"]) if Args.testnet else bit.Key.from_hex(dataDict["privateKey"])


def deriveBIP39Words():
    global dataDict
    mnemo = Mnemonic(Args.language)
    byte_array = bytearray.fromhex(dataDict["privateKey"])
    dataDict["BIP39Words"] = mnemo.to_mnemonic(byte_array)


def derivePublic():
    key = bit.PrivateKeyTestnet.from_hex(dataDict["privateKey"]) if Args.testnet else bit.Key.from_hex(dataDict["privateKey"])
    dataDict["publicKey"] = key.public_key
    dataDict["publicKey_uncompressed"] = key._pk.public_key.format(compressed=False)


def restoreWallet():
    global dataDict
    global Args
    mnemo = Mnemonic(Args.language)
    dataDict["BIP39Words"] = Args.restore
    ent = mnemo.to_entropy(dataDict["BIP39Words"])
    dataDict["privateKey"] = hexlify(ent).decode("utf-8")


def hash160():
    """
        Given a public key (can be hex string or bytes) returns the RIPMED(SHA256(pub))
        Returns the hash160 in bytes (or False on error)
    """
    global dataDict
    hashkey = hashlib.sha256(dataDict["publicKey"]).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashkey)
    h160 = ripemd160.digest()
    dataDict["hash160"] = h160


def pub2bitaddr(version, pubKey):
    """ 
        Creates the address from the public key
        "Bitcoin Stye" : 
            do ripmed(sha)
            add version byte
            add 4 bytes of check
            return in base58
    """
    if not dataDict["hash160"]:
        return False
    # Add version to the public key (hex)
    ver = version + dataDict["hash160"].hex()
    # compute the double sha256 control
    check = hashlib.sha256(hashlib.sha256(bytes.fromhex(ver)).digest()).hexdigest()
    # compose : version + publickey + first 8 bytes of check 
    vercheck = ver + check[:8]
    # encode in base58
    addr = base58.b58encode(bytes.fromhex(vercheck))
    return addr.decode("utf-8")


def deriveWIF(prefix, compressed):
    """ 
        WIF Generation
        Create WIF (Wallet Improt Format) for 
        Bitcoin-like wallets
    """
    exk = prefix + dataDict["privateKey"]
    if compressed :
        exk = exk + "01"
    cks = hashlib.sha256(hashlib.sha256(bytes.fromhex(exk)).digest()).hexdigest()[:8]
    csk = exk+cks
    wif = base58.b58encode(bytes.fromhex(csk)).decode("utf-8")
    return wif

def deriveBIP38():
    if Args.password == None:
        return "Cannot generate BIP38 encrypted key, no password provided. Use '-p' or '--password'"
    privkey = dataDict["privateKey"]
    passphrase = Args.password
    return format(encrypt(PrivateKey(privkey),passphrase), "encwif")

def deriveEVMaddress():
    # get the uncompressed public key (remove first byte and concat X and Y) 
    pu = dataDict["publicKey_uncompressed"].hex()[2:]
    # hash uncompressed public key with keccak algorithm
    k = Web3.keccak(hexstr=pu)
    # add "0x" at the beginning to show it's hex, the get the last 20 bytes of it
    addr = "0x"+k.hex()[-40:]
    # Turn in into CheCKSuM addresse format (case sensitive)
    return Web3.toChecksumAddress(addr)

def deriveUTCJSON(indent = True):
    if Args.password == None:
        return "Cannot generate JSON-UTC file, no password provided. Use '-p' or '--password'"
    jutc= eth_keyfile.create_keyfile_json(bytes.fromhex(dataDict["privateKey"]), Args.password.encode("utf-8"))
    
    if indent:
        return  re.sub(r'^|\n'  ,'\n\t\t'  , json.dumps(jutc,indent=4))
    else:
        return jutc

def EVMJson():
    eth = {}
    eth['address'] = deriveEVMaddress()
    if Args.password != None:
        eth['UTC-JSON'] = deriveUTCJSON(False)
    return eth

####################################################################################################
##
## RESULT JSON EXPORTING FUNCTIONS
##

def jsonExportPrivate():
    global JOut
    private = {}
    private['privateKey']=dataDict["privateKey"]
    private['publicKey']=dataDict["publicKey"].hex()
    private['publicKeyUncompressed']=dataDict["publicKey_uncompressed"].hex()
    private['bip39words']=dataDict["BIP39Words"]
    private['network'] = "testnet" if Args.testnet else "main"
    JOut['wallet'] = {}
    JOut['keys'] = private

def jsonExportBitcoinWallet():
    global JOut
    bitcoin = {}
    
    key = dataDict["bitcoinKey"]
    bitcoin['hash160']=dataDict["hash160"].hex()
    prefix = "EF" if Args.testnet else "80"
    bitcoin['WIF']=deriveWIF(prefix, True)
    if Args.password != None:
            bitcoin['BIP38']=deriveBIP38()
    bitcoin['address']=key.address
    bitcoin['segwitAddress']=key.segwit_address
    bitcoin['bech32'] = bech32.encode('tb', 0, dataDict["hash160"]) if Args.testnet else bech32.encode('bc', 0, dataDict["hash160"]) 
    bitcoin['network'] = "testnet" if Args.testnet else "main"

    JOut['wallet']['bitcoin'] = bitcoin


def jsonExportEthereumWallet():
    global JOut
    JOut['wallet']['ethereum'] = EVMJson()


def jsonExportEthereumClassicWallet():
    global JOut
    JOut['wallet']['ethereumClassic'] = EVMJson()


def jsonExportQuadransWallet():
    global JOut
    JOut['wallet']['quadrans'] = EVMJson()


def jsonExportDashWallet():
    global JOut
    dash = {}
    prefix = "EF" if Args.testnet else "CC"
    dash['network'] = "testnet" if Args.testnet else "main"
    dash['WIF'] = deriveWIF(prefix, True)

    # Address generation is same as Bitcoin, it only changes the version byte
    dash['addrP2PKH'] = pub2bitaddr("8c", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("4c", dataDict["publicKey"]) 
    dash['addrP2SH'] = pub2bitaddr("13", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("10", dataDict["publicKey"])
    JOut['wallet']['dash'] = dash


def jsonExportLiteCoinWallet():
    global JOut
    lite = {}
    prefix = "EF" if Args.testnet else "B0"
    lite['WIF'] = deriveWIF(prefix, True)
    # Address generation is same as Bitcoin, it only changes the version byte
    lite['address'] = pub2bitaddr("6f", dataDict["publicKey"]) if Args.testnet else pub2bitaddr("30", dataDict["publicKey"])
    if not Args.testnet:
        lite['bech32'] = bech32.encode('ltc', 0, dataDict["hash160"])
    lite['network'] = "testnet" if Args.testnet else "main"
    JOut['wallet']['litecoin'] = lite




def main():    
    global dataDict
    global Args
    global JOut


    ## Get all data into JOut json object
    jsonExportPrivate()
    if Args.blockchain in ["all","Bitcoin", "btc", "xbt"]:
        jsonExportBitcoinWallet()
    if Args.blockchain in ["all","Ethereum", "eth"]:
        jsonExportEthereumWallet()
    if Args.blockchain in ["all","EthereumClassic", "etc"]:
        jsonExportEthereumClassicWallet()
    if Args.blockchain in ["all","Quadrans", "qdc"]:
        jsonExportQuadransWallet()
    if Args.blockchain in ["all","Dash", "dash"]:
        jsonExportDashWallet()
    if Args.blockchain in ["all","Litecoin", "ltc"]:
        jsonExportLiteCoinWallet()

    ## How to output?
    if Args.json :
        print (json.dumps(JOut,indent=4))
    else :
        cli.printSeed(JOut["keys"], Args)
        if Args.blockchain in ["all","Bitcoin", "btc", "xbt"]:
            cli.printBitcoinWallet(JOut["wallet"], Args)
        if Args.blockchain in ["all","Ethereum", "eth"]:
            cli.printEthereumWallet(JOut["wallet"], Args, deriveUTCJSON)
        if Args.blockchain in ["all","EthereumClassic", "etc"]:
            cli.printEthereumClassicWallet(JOut["wallet"], Args, deriveUTCJSON)
        if Args.blockchain in ["all","Quadrans", "qdc"]:
            cli.printQuadransWallet(JOut["wallet"], Args, deriveUTCJSON)
        if Args.blockchain in ["all","Dash", "dash"]:
            cli.printDashWallet(JOut["wallet"])
        if Args.blockchain in ["all","Litecoin", "ltc"]:
            cli.printLiteCoinWallet(JOut["wallet"], Args)



if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

if __name__ == "__main__": 
    # What does the user want?
    # parseArguments()

    Args = cli.parse_arguments() # temporary

    # How to generate private key?
    if (Args.restore):
        restoreWallet()
    else :
        generatePrivateKey()
    # Gather other data
    deriveBIP39Words()
    derivePublic()
    hash160()

    main()

