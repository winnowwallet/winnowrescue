# Winnow Rescue: design

Winnow Rescue is a rescue-only Bitcoin tool. From recovery words, a single key or another
wallet's export, it finds the coins in an old wallet and moves all of them, in one transaction,
into a taproot address the person already has. Then it keeps nothing. It is not for everyday use
and privacy is not its design goal: discovery asks an indexing server, and the tool says what that
server learns before it asks. Nothing in it is novel; every check it makes is a published standard
held to published vectors, which is the point for the one program that handles raw keys.

The core is a Rust library that a wallet can embed, so the restore can end inside the wallet the
person already uses. The standalone product is a desktop command-line tool and a desktop window.
Winnow itself embeds nothing and carries none of this code.

## Scope: any wallet, by what the person has

| They have | Rescue does |
| --- | --- |
| BIP39 words, 12 to 24, passphrase or not | BIP44, 49, 84 and 86; accounts 0 upward until two in a row are empty; receive and change; then the quirk rows |
| A wallet with habits | Bitcoin Core legacy HD `m/0'/0'/i'`; BRD and MultiBit HD `m/0'/0/i`; Samourai's extra BIP84 accounts; standard account 0 for Exodus, Jaxx, Trust, Atomic and Coinbase Wallet; Blockchain.com accounts; Ledger and Trezor passphrase wallets; any typed path |
| An Electrum seed | 2.x standard (`m/0/i`, `m/1/i`, legacy) and 2.x segwit (`m/0'/0/i`, `m/0'/1/i`). Two-factor seeds are out: a service holds a key. 1.x seeds later |
| WIF, a mini private key, a 32-byte hex secret, a Bitcoin Core `dumpwallet` file | compressed and uncompressed P2PKH; P2WPKH and nested for a compressed key; the file is read as WIFs |
| xprv, or an account xprv, yprv or zprv | the same walk from that root or account |
| xpub, ypub, zpub, a descriptor, a BIP388 policy or a shared vault made elsewhere | discover and report; sign where a key is held, otherwise build the sweep as a PSBT for the device or wallet that can sign |
| A Privy embedded wallet | a source only: Privy exports its plain secp256k1 key in a web environment; copied out, it is an ordinary key or words import, and BIP84 or BIP86 reproduces the address. Never a destination, never a sign-in |
| Out | Lightning channels; other coins and forks; hardware-only setups with no key material (the PSBT hand-off is the later door); service-cosigned wallets; BIP47; Armory; BIP38 until it is wanted; an emergency wallet of its own (a later feature of the standalone app only) |

## The restore: five screens, the same everywhere

1. Words, a key or a file. A typo is named by position, never silently accepted.
2. The first address of every path, to confirm against the old wallet before anything is scanned.
   This catches a wrong passphrase or path.
3. The coins found, with a live count and a button to search further.
4. The review: every input by type and amount, the one destination, the exact fee in sats and as a
   share of the total. Hold to send.
5. Done, waiting, or stalled, with the next step.

The screens are a `Flow` state machine in the core: a shell renders a step and sends back an
action, and every sentence a person reads comes from a string table in the core, so no platform
says what another does not. Refusals are named on screen, never silent.

## Checks, each a testable rule with its standard

- BIP39 wordlist and checksum; a failing phrase names the wrong word by position. WIF Base58Check
  and version byte; a test-network key never gets a mainnet sweep.
- Destination checksum, Base58Check or bech32m; a typo is refused, not sent to. The destination is
  P2TR only. Descriptor checksum before any derivation (BIP380).
- Derive and compare: the first address of every path is shown before any scan.
- Every coin the indexer reports is proved: fetch its transaction, hash it to the txid, check the
  output pays the derived script, check the merkle proof and the header's proof of work against a
  header chain validated from genesis locally. A server can hide coins, never invent them; a second
  indexer catches hiding. Unconfirmed coins are not rescuable yet; confirmations are shown.
- Segwit and taproot inputs sign with the amount committed (BIP143, BIP341); legacy inputs fetch
  the previous transaction first, so the fee shown is the fee paid.
- Fee refused above a tenth of the total, or a rate above double the higher of two estimates.
  One destination, every coin, no change, RBF sequence, anti-fee-sniping locktime; every signature
  re-verified before broadcast; broadcast to the indexer and, where the host has peers, to peers.
- Secrets are zeroized types that live for the session: never written, never serialized, never
  logged (the core has no logging facade), never returned across a language boundary.

## Discovery with no birthday

Compact filters are out: a phone cannot read the chain's filters, and five years is the most any
bounded scan reaches. Discovery asks an indexer, Electrum protocol first (one connection answers
thousands of scripthash queries a minute and reports mempool state), Esplora as the fallback for
history and broadcast, with every claim proved as above against a header chain the core validates
from genesis. The consent sentence says what the server learns; a SOCKS route hides the address.

Thousands of addresses and no birthday are handled by a plan, not a scan: tier 1 is the four
purposes, accounts 0 to 2, both chains, gap 20; a hit widens that account's gap to 100 and opens
the next account until two in a row are empty; tier 2 is the quirk rows; tier 3 a typed path;
"search further" raises the gap to 1,000 for accounts that hit. Progress is saved as public data
so an interrupted restore resumes once the words are entered again; the secret never is.

## Platforms

Hosts embed the core through generated bindings (Swift and Kotlin) or a wasm package, render the
five steps in their own look, and supply their own receive address. The standalone product is a
SwiftUI-free, pure-Rust desktop window and a command-line tool with an offline signing mode, on
macOS, Linux and Windows. Ruled out: a webview user interface (the phrase would pass through
JavaScript strings), Flutter (a large runtime and Dart strings holding the phrase), and any web page.

## Moving the coins into Winnow

The destination is an address the person already owns. For Winnow, a universal link asks the app
for a receive address with a nonce and a return link, Winnow shows its own confirmation screen,
answers once per nonce, and the address is shown beside Winnow's for a last look; Winnow's Receive
QR works too, including across two phones. Winnow adds one client-neutral route for this.

## Send somewhere else: the exchange check (optional, last)

From the indexer alone, a destination with many incoming payments is labelled as looking like a
shared custodial deposit address, and a never-seen one as likely fresh self-custody. With a login
to the exchange (its OAuth, or a read-only API key, refused if it can trade or withdraw), one
question is asked: is this exact address in your BTC deposit-address list on the Bitcoin network.
Yes or no, then nothing is kept. The proof is the list, never the login; the network is part of the
check; Rescue never fetches or supplies a deposit address.
