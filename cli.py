from sty import fg, bg, ef, rs
import argparse

# PRINTING FUNCTION

def _banner(color, name):
    """
        Print a _banner with a color and name of the coin
    """
    print()
    bgc = bg(color) if isinstance(color,str) else bg(*color)
    print(bgc + ef.bold + "{:^20}".format(name) + rs.bg + rs.bold_dim)


def printSeed(keys, args):
    ## DISPLAY RESULTS TO STDOUT
    _banner("white","Seed")
    print("\tPrivate key: ", keys['privateKey'])
    print("\tPublic key   ", keys['publicKey'], " (Secp256k1 compressed)")
    print("\tPublic key:  ", keys['publicKeyUncompressed'], " (uncompressed)")

    if args.wordlist:
        print("\tBIP39 Seed:     ", end="")
        for idx, word in enumerate(keys['bip39words'].split(" ")):
            print("{:2}){:12}\t".format(idx+1,word), end="")
            if ((idx+1) % 6 == 0):
                print("\n\t\t\t", end="")
    else: 
        print("\tBIP39 Seed:  ", keys['bip39words'])


def printBitcoinWallet(wallet, args):
    _banner((255, 150, 50), "Bitcoin")
    print("\tNetwork:     ", wallet['bitcoin']['network'])
    print("\tHash160:     ", wallet['bitcoin']['hash160'], "(ripmed160(sha256(pub)))")
    print("\tWIF:         ", wallet['bitcoin']['WIF'])
    if args.password != None:
        print("\tBIP38:       ", wallet['bitcoin']['BIP38'], "(encrypted private key)")
    print("\tAddress:     ", wallet['bitcoin']['address'], " (P2PKH)")
    print("\tSegWit Addr: ", wallet['bitcoin']['segwitAddress'])
    print("\tBech32 Addr: ", wallet['bitcoin']['bech32'])


def printEthereumWallet(wallet, args, deriveUTCJSON):
    _banner((150, 150, 150),"Ethereum")
    print("\tAddress:     ", wallet['ethereum']['address'])
    if args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printEthereumClassicWallet(wallet, args, deriveUTCJSON):
    _banner((0, 150, 0),"EthereumClassic")
    print("\tAddress:     ", wallet['ethereumClassic']['address'])
    if args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printQuadransWallet(wallet, args, deriveUTCJSON):
    _banner((150, 0, 150),"Quadrans")
    print("\tAddress:     ", wallet['quadrans']['address'])
    if args.password != None:
        print("\tUTC-JSON:    ", deriveUTCJSON())


def printDashWallet(wallet):
    _banner((50, 50, 255),"Dash")
    print("\tNetwork:     ", wallet['dash']['network'])
    print("\tWIF:         ", wallet['dash']['WIF'])
    print("\tAddress:     ", wallet['dash']['addrP2PKH'], " (P2PKH)")
    print("\tAddress:     ", wallet['dash']['addrP2SH'], " (P2SH)")


def printLiteCoinWallet(wallet, args):
    _banner((100, 100, 100),"Litecoin")
    print("\tNetwork:     ", wallet['litecoin']['network'])
    print("\tWIF:         ", wallet['litecoin']['WIF'])
    print("\tAddress:     ", wallet['litecoin']['address'], " (P2PKH)")
    if not args.testnet:
        print("\tBech32 Addr: ", wallet['litecoin']['bech32'])



# INPUT FUNCTIONS (ARGUMENTS)

def parse_arguments():
    """ parsing arguments """
    parser = argparse.ArgumentParser("Vanilla Wallet command line arguments")
    parser.add_argument("-bc", "--blockchain", help="Optional, the blockchain the wallet is generater for. Default: all", 
        type=str, required=False, default="all",
        choices=[
            "all",
            "Bitcoin", "btc", "xbt", 
            "Litecoin", "ltc",
            "Ethereum", "eth",
            "EthereumClassic", "etc",
            "Quadrans", "qdc",
            "Dash", "dash"
            ])

    parser.add_argument("-wn", "--wordnumber", help="Optional, print BIP39 word list in numbered table", dest='wordlist', action='store_const', const=True, default=False)
    parser.add_argument("-e", "--entropy", help="An optional random string in case you prefer providing your own entropy", type=str, required=False)
    parser.add_argument("-l", "--language", help="Optional, the language for the mnemonic words list (BIP39). Default: english", type=str, required=False, default="english", choices=["english", "chinese_simplified", "chinese_traditional", "french", "italian", "japanese", "korean", "spanish"])
    parser.add_argument("-t", "--testnet", help="Generate addresses for test net (default is main net)", dest='testnet', action='store_const', const=True, default=False)
    parser.add_argument("-r", "--restore", help="Restore a wallet from BIP39 word list", dest="restore", type=str, required=False)
    parser.add_argument("-p", "--password", help="Password for wallet encryption", dest="password", type=str, required=False)
    parser.add_argument("-j", "--json", help="Produce only json output", dest='json', action='store_const', const=True, default=False)
    
    ## Yet to be implemented
    parser.add_argument("-d", "--directory", help="An optional where to save produced files (json and qr codes)", type=str, required=False, default=".")
    parser.add_argument("-q", "--qrcode", help="Generate qrcodes for addresses and keys", dest='qrcode', action='store_const', const=True, default=False)

    return parser.parse_args()