//  ----------------------------------------------------------------------
//  band implementation and framework for stateless distributed group identity
//  for automating the tribe (vs. automating the state)
//
//  MIT License
//
//  Copyright (c) 2019 Charles Perkins
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//
//  ----------------------------------------------------------------------

package inband

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	//"encoding/hex"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	//	"flag"
	"github.com/io-core/Attest/s2r"
	"io/ioutil"
	"os"
	//	"path/filepath"
	"strconv"
	"strings"
	//"time"
)

// DESIGN

// Tribes have a memory while states have a history
// Tribes have a way while states have a code
// Sub-groups of the tribe delegate one of their own to the chief for service while kings designate officials to govern subjects.
// Delegates may expect rewards from their group while officials demand tribute from their subjects

// Worth of a system can be measured on reduction of: Death, Violation, Hunger, Exposure, Displacement, Isolation, Extraction, Limitation.
// Democracy can be seen as a political alloy of the state and the tribe with fascism at one end and anarcho-something at the other
// Socialism can be seen as an economic alloy of the state and the tribe with capitalism at one end and communism at the other

// An Id is formed by creating a private/public key pair and taking the shah of the signed nonce-and-public-key.

// If the Id is for a band then it  makes a claim with its Id as the By, Er, and Ee and the name as the St.
// The band's private key may then be discarded as it should never be used again.

// The private key should be kept for an individual rather than a band. The private key should not be transmitted.

// A claim of association takes the Idshahs of a (claim)By of (claim)Er to (claim)Ee and the Sdshah of a Stmt (St) and
// produces a Seal of the By-pkey-signed Affirm + C + Er + Ee + St.

// A band will have its founders when at least two Ids symmetrically make and exchange 'in' upvote claims
// of association with each other's Ee the band's Er
// Each individual will also create their own name claim.
// an individual may change their name by making a new name claim and downvoting their old one.
// nicnames are when an individual makes a name claim for someone else.
// individuals can claim or have bestowed on them other things such as email addresses, phone numbers, titles, etc.
// other individuals can dispute the claims.
// Global history is not maintained but an individual may keep and share a 'diary' of personal history
// A 'in upvote' is the Stmt.Said "IN" and Affirm is 'true'. 'in downvote' is the same but where 'affirm' is false.
// A claim with the same By, Er, Ee, and St but a higher-numbered C supplants earlier claims with teh same By, Er, Ee, and St.
// An Id may be considered to be a member so long as it has more upvotes than downvotes by other members. This is a circular relation.
// Other relastionships may be described between two individuals.
// A Moot is when an Ident has a Visit with several other Idents requesting new Claims from them.
// Anyone can Moot. Someone who Moots a lot might be made a leader, or might be downvoted out of the band to stop the bother.
// Claims are affirmative or negative.
// a Dog is an automaton with an Id that acts on its view of the consensus of the band.
// An individual identity

// a role is just another name for a person
// SPONSOR shah + AFFIRM shah Topic name == introduce person as name
// name can be a utf8 string or a gif or a jpeg or a ring-tone or...

// When mooted by a mooter regarding a claim, the mootee can affirm true or false or decline to reply.
// It is expected that if a mootee has affirmed a leader and the leader is a mooter then the mootee should not decline to reply.

// some CLAIMs: (format: Id(claimant) affirm Id(individual) Shah(stmt) Id(individual|band)|Shah(stmt)
// IN:        claimaint says individual 'IN' band
// <DUTY>:    claimaint says individual 'SPEAKER'|'LEADER'|'SCAPEGOAT'|'COOK'|'CLERK'|'PROGNOSTICATOR'|'<whatever>' for band
// <STATUS>:  claimaint says individual 'SAGE'|'CONTRIBUTOR'|'JOURNEYMAN'|'BRO/SIS'|'ELDER'|'FULL-MEMBER'|'ELECT'|'COMPETENT'|'DUES-PAID'|'<something>' in band
// MY,<ROLE>: claimaint says individual 'MY' 'FRIEND'|'PARTNER'|'MENTOR'
// NAME:      claimaint says claimant 'NAME' '<name>'
// EMAIL:     claimaint says claimant 'EMAIL' '<email address>'
// IP:        claimaint says claimant 'IP' '<ip address>'
// NICNAME:   claimaint says individual 'NAME' '<name>'

// convention determines the meaning and usefullness of claims.
// automation may reify convention.
// claim evaluation happens locally by individuals or dogs (automated individuals.)

// feature targets:
// Content warnings
// Selectable hop distances in clients
// A more stable client experiance
// Hiding content you don't want to see
// Deleting content you don't want to see locally
// Muting users
// Being able to block a pub and everyone connected to it (similar to a instance domain mute on Masto)
// Posting to only people you follow
// Posting to only people on a certain list
// Seeing content only from people on a certain list
// Image captions for the visually impaired
// A way to report a scuttler's bad behaviour to your friends with evidence
// A way to select my actual locale (en-gb) instead of `merican English
// A way to route Scuttlebutt through Tor in the client's UI
// A integrated way to encrypt your local .ssb data
// Ability to automatically scrub metadata from your posts (e.g. EXIF data in photos)
// Being able to lock down your account so people who want to follow you need to be approved
// A way to prevent your posts being indexed by malicious crawlers (meta issue)

type Shah [32]byte // In this code if a variable name is two letters, it contains a Shah

type Stmt struct { 
	Said []byte
	Sd   Shah // Represents this statement
}

type Claim struct {
	Affirm bool
	C      uint64 // Increment for superceding claims
	By     Shah   // - To statements consisting
	Er     Shah   // - of a public key
	Ee     Shah   // - (identity statements)
	St     Shah
	Sig    []byte
	Cl     Shah // Represents this claim
}

var Me Shah // of Stmt of identity
var Yo Shah // of Claim of name by identity
var Nm Shah // of Stmt of name

var MyPrivateKeyType string
var MyPrivateCert []byte
var MyPrivateRSAKey *rsa.PrivateKey
var MyPrivateEDKey *ed25519.PrivateKey

var Stmts map[Shah]Stmt
var Claims map[Shah]*Claim

var Idents map[Shah]*Claim
var Bands map[Shah]*Claim

func (b Shah) Consider(c *Claim) {
}

func (b Shah) Moot(debug bool) {
	if debug {
		//i := All[b]
		//fmt.Println("Mooting in", i.I.Is())
	}
}

func (i Stmt) Visit(debug bool) {
	if debug {
		fmt.Println("Visiting", i.Is())
	}
}

func (i Stmt) Is() string {
	//return string(Stmts[i.St].Said)
	return "somebody"
}

func getKeys(typ, pkfn string) (rsakey *rsa.PrivateKey, edkey *ed25519.PrivateKey, pkb, bkb []byte, err error) {
	var bkt []byte
	if typ == "rsa" {
		if pkb, err = ioutil.ReadFile(pkfn + "/id_rsa"); err == nil {
			if bkt, err = ioutil.ReadFile(pkfn + "/id_rsa.pub"); err == nil {

				bka := strings.Split(string(bkt), " ")
				l := len(bka)
				if l < 3 {
					err = errors.New("too few fields in public key file")
				} else {
					if l > 3 { // count from end because options may contain quoted spaces
						bkb = []byte(bka[l-2] + " " + bka[l-3] + " Id")
					} else {
						bkb = []byte(bka[0] + " " + bka[1] + " Id")
					}
				}
				privPem, _ := pem.Decode(pkb)
				privPemBytes := privPem.Bytes
				rsakey, err = x509.ParsePKCS1PrivateKey(privPemBytes)
			}
		}
	} else if typ == "ed25519" {
		if pkb, err = ioutil.ReadFile(pkfn + "/id_ed25519"); err == nil {
			if bkt, err = ioutil.ReadFile(pkfn + "/id_ed25519.pub"); err == nil {

				bka := strings.Split(string(bkt), " ")
				l := len(bka)
				if l < 3 {
					err = errors.New("too few fields in public key file")
				} else {
					if l > 3 { // count from end because options may contain quoted spaces
						bkb = []byte(bka[l-2] + " " + bka[l-3] + " Id")
					} else {
						bkb = []byte(bka[0] + " " + bka[1] + " Id")
					}
				}
				privPem, _ := pem.Decode(pkb)
				privPemBytes := privPem.Bytes
				ek := ed25519.PrivateKey(privPemBytes)
				edkey = &ek
			}
		}
	} else if typ == "ssb" {
		err = errors.New("ssb not implemented yet.")
	} else {
		err = errors.New("Don't know how to load " + typ + " keys on init.")
	}

	return rsakey, edkey, pkb, bkb, err
}

func MakeClaim(affirm bool, count uint64, by, er, ee, st Shah) (c *Claim, err error) {
	var sig []byte
	var a byte

	if affirm {
		a = 0
	} else {
		a = 255
	}

	cbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(cbuf, count)

	if sig, err = Sign(append([]byte{1, 0, 0, 0, 0, 0, 0, a},
		append(cbuf,
			append(by[:],
				append(er[:],
					append(ee[:],
						st[:]...)...)...)...)...)); err == nil {

		c = &Claim{affirm, count, by, er, ee, st, sig, sha256.Sum256(sig)}
	}

	return c, err
}

func Untampered(c *Claim) (ok bool) {
    s, e := Stmts[c.By]
    if !e {
         ok = false
    } else {

         abuf := make([]byte, 8)
         abuf[0] = 1 //version 1 ... bytes 1-6 should be zero
         if c.Affirm {
                 abuf[7] = 0
         } else {
                 abuf[7] = 255
         }

         cbuf := make([]byte, 8)
         binary.LittleEndian.PutUint64(cbuf, c.C)

         q := append(abuf,
                 append(cbuf,
                         append(c.By[:],
                                 append(c.Er[:],
                                         append(c.Ee[:],
                                                 c.St[:]...)...)...)...)...)
         
         if err := Verify(q, c.Sig, string(s.Said)); err == nil {
		ok = true
         }
    }
    return ok
}

func claim2string(h string, c *Claim) string {
	return fmt.Sprintf(h+"\n") +
		fmt.Sprintf("%t\n", c.Affirm) +
		fmt.Sprintf("%d\n", c.C) +
		base64.StdEncoding.EncodeToString(c.By[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.Er[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.Ee[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.St[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.Sig) + "\n" +
		base64.StdEncoding.EncodeToString(c.Cl[:]) + "\n"
}

func stmt2string(h string, s Stmt) string {
	return fmt.Sprintf(h+"\n") +
		base64.StdEncoding.EncodeToString(s.Said) + "\n" +
		base64.StdEncoding.EncodeToString(s.Sd[:]) + "\n"
}

func NewBand( n string ) (err error) {
	var pubk ed25519.PublicKey
	var privk []byte
	var bnc *Claim
	
	

	if pubk,privk,err = ed25519.GenerateKey(nil); err == nil {
		
		//fmt.Println("new public key:",base64.StdEncoding.EncodeToString(pubk))
		s,_:=ssh.NewPublicKey(pubk)
		spk:=ssh.MarshalAuthorizedKey(s)
		
        	it := sha256.Sum256(spk)
        	Stmts[it] = Stmt{spk, sha256.Sum256(spk)}

                nm := sha256.Sum256([]byte(n))
                Stmts[nm] = Stmt{[]byte(n), nm}

                bnc, err = MakeClaim(true, 18446744073709551615, it, it, it, nm)

		if 1==2 {fmt.Println(privk,bnc)}
	}
	return err
}

func initFromKeys(typ, pfn, mfn, n string) (err error) {
	var bkb []byte
	var mnc *Claim

	MyPrivateKeyType = typ
	if MyPrivateRSAKey, MyPrivateEDKey, MyPrivateCert, bkb, err = getKeys(typ, pfn); err == nil {

		Me = sha256.Sum256(bkb)
		Stmts[Me] = Stmt{bkb, sha256.Sum256(bkb)}
		Nm = sha256.Sum256([]byte(n))

		Stmts[Nm] = Stmt{[]byte(n), Nm}

		if mnc, err = MakeClaim(true, 0, Me, Me, Me, Nm); err == nil {
			Yo = mnc.Cl
			Claims[Yo] = mnc
			Idents[Yo] = mnc
			err = persist(mfn)
		}
	}

	return err
}

func recallFromFile(mfn string) (err error) {
	var b, x []byte
	//var self Ident

	if b, err = ioutil.ReadFile(mfn); err == nil {
		a := strings.Split(string(b), "\n:")
		for _, e := range a {
			l := strings.Split(e, ":\n")
			if err == nil {
				if l[0] == ":MYTYPE" {
					MyPrivateKeyType = l[1]
				} else if l[0] == "MYPRIVATE" {
					MyPrivateCert = []byte(l[1])
					privPem, _ := pem.Decode(MyPrivateCert)
					privPemBytes := privPem.Bytes
					if MyPrivateKeyType == "rsa" {
						MyPrivateRSAKey, err = x509.ParsePKCS1PrivateKey(privPemBytes)
					} else if MyPrivateKeyType == "ed25519" {
						ek := ed25519.PrivateKey(privPemBytes)
						MyPrivateEDKey = &ek
					}

				} else if l[0] == "MYID" {
					if x, err = base64.StdEncoding.DecodeString(l[1]); err == nil {
						copy(Me[:], x)

					}
				} else if l[0] == "MYNM" {
					if x, err = base64.StdEncoding.DecodeString(l[1]); err == nil {
						copy(Yo[:], x)
					}
				} else if l[0] == "STMT" {
					var txt []byte
					var xb Shah
					ll := strings.Split(l[1], "\n")
					if len(ll) > 1 {

						if txt, err = base64.StdEncoding.DecodeString(ll[0]); err == nil {

							if x, err = base64.StdEncoding.DecodeString(ll[1]); err == nil {
								copy(xb[:], x)
							}
						}
					}

					Stmts[xb] = Stmt{txt, xb}
				} else if l[0] == "CLAIM" {
					c := new(Claim)
					ll := strings.Split(l[1], "\n")
					if len(ll) > 7 {
						var txt []byte
						if ll[0] == "true" {
							c.Affirm = true
						} else {
							c.Affirm = false
						}
						count := 0
						if count, err = strconv.Atoi(ll[1]); err == nil {
							c.C = uint64(count)
						}
						if x, err = base64.StdEncoding.DecodeString(ll[2]); err == nil {
							copy(c.By[:], x)
						}
						if x, err = base64.StdEncoding.DecodeString(ll[3]); err == nil {
							copy(c.Er[:], x)
						}
						if x, err = base64.StdEncoding.DecodeString(ll[4]); err == nil {
							copy(c.Ee[:], x)
						}
						if x, err = base64.StdEncoding.DecodeString(ll[5]); err == nil {
							copy(c.St[:], x)
						}
						if txt, err = base64.StdEncoding.DecodeString(ll[6]); err == nil {
							c.Sig = txt
						}
						if x, err = base64.StdEncoding.DecodeString(ll[7]); err == nil {
							copy(c.Cl[:], x)
						}
						if Untampered(c) {
                                                               Claims[c.Cl] = c
                                                                if (c.By == c.Er) && (c.Er == c.Ee) {
                                                                        Idents[c.Cl] = c
                                                                }
						}else{
							err = errors.New("Unable to verify claim "+ base64.StdEncoding.EncodeToString(c.Cl[:]))
						}
					} else {

						err = errors.New("too few lines in claim entry")
					}

				}
			}
		}

		var lk bool
		var mnc *Claim

		mnc, lk = Claims[Yo]
		if !lk {
			err = errors.New("My Name Claim not found")
		} else {
			_, lk = Stmts[mnc.St]
			if !lk {
				err = errors.New("My Name Statement not found")
			} else {
				Nm = mnc.St
			}
		}

	}
	return err

}

func recall(typ, pfn, mfn, n string, init, force bool) (err error) {

	
	//All = make(map[Shah]ICCC) // individual/band, By chain, Er chain, Ee chain for this Id
	//Topics = make(map[Shah]CChain)
	Stmts = make(map[Shah]Stmt)
	Claims = make(map[Shah]*Claim)
	Idents = make(map[Shah]*Claim)
        Bands = make(map[Shah]*Claim)

	if _, mferr := os.Stat(mfn); mferr != nil {
		if !init {
			err = errors.New("The memory file does not exist and initialization was not requested.")
		} else {
			// initializing persistent store
			err = initFromKeys(typ, pfn, mfn, n)
		}
	} else {
		if init {
			if force {
				// re-initializing persistent store
				err = initFromKeys(typ, pfn, mfn, n)
			} else {
				err = errors.New("The memory file already exists and force was not requested.")
			}
		} else {
			// loading from persistent store

			err = recallFromFile(mfn)
		}
	}
	if err == nil {
		mnm, ok := Stmts[Nm]
		if !ok {
			err = errors.New("Lost my name")
		}
		fmt.Println("         Hello ", string(mnm.Said))
		fmt.Println("           me:", base64.StdEncoding.EncodeToString(Me[:]))
		fmt.Println("           yo:", base64.StdEncoding.EncodeToString(Yo[:]))
		fmt.Println("           nm:", base64.StdEncoding.EncodeToString(Nm[:]))
	}

	return err
}

func persist(mfn string) (err error) {
	f, err := os.Create(mfn)
	defer f.Close()
	if err == nil {
		_, err = f.WriteString(":MYTYPE:\n")
	}
	if err == nil {
		_, err = f.WriteString(MyPrivateKeyType + "\n")
	}
	if err == nil {
		_, err = f.WriteString(":MYPRIVATE:\n")
	}
	if err == nil {
		_, err = f.WriteString(string(MyPrivateCert) + "\n")
	}
	if err == nil {
		_, err = f.WriteString(":MYID:\n")
	}
	if err == nil {
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(Me[:]) + "\n")
	}
	if err == nil {
		_, err = f.WriteString(":MYNM:\n")
	}
	if err == nil {
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(Yo[:]) + "\n")
	}
	slf, ok := Stmts[Me]
	if !ok {
		err = errors.New("Persist: Lost myself")
	}
	if err == nil {
		_, err = f.WriteString(stmt2string(":STMT:", slf))
	}
	mnm, ok := Stmts[Nm]
	if !ok {
		err = errors.New("Persist: Lost my name")
	}
	if err == nil {
		_, err = f.WriteString(stmt2string(":STMT:", mnm))
	}
	if err == nil {
		for i, s := range Stmts {
			if (i != Me) && (i != Nm) {
				if err == nil {
					_, err = f.WriteString(stmt2string(":STMT:", s))
				}
			}
		}
	}
	if err == nil {
		for _, c := range Claims {
			if err == nil {
				_, err = f.WriteString(claim2string(":CLAIM:", c))
			}
		}
	}

	return err
}

func Startup(typ, pfn, mfn, n string, init, force, debug bool) (err error) {
	if debug {
		fmt.Println("loading keys identities and claims...")
		//fmt.Println(typ, pfn, mfn, n, Me, Bands, All, Stmts, Claims)
	}

	if err = recall(typ, pfn, mfn, n, init, force); err != nil {

		if debug {
			fmt.Println("loaded!")
		}
	}

	return err
}

func Shutdown(typ, pfn, mfn string, debug bool) (err error) {
	if debug {
		fmt.Println("storing identities and claims...")

	}

	//if err = persist(mfn); err != nil {

	if debug {
		fmt.Println("stored!")
	}
	//}
	return err
}

func Sign(contents []byte) (encoded []byte, err error) {
	hashed := sha256.Sum256(contents)

	signature := []byte{}
	if MyPrivateKeyType == "rsa" {
		if signature, err = rsa.SignPKCS1v15(rand.Reader, MyPrivateRSAKey, crypto.SHA256, hashed[:]); err == nil {
			encoded = signature
		}
	} else {
		pvk := make([]byte, 64)
		pvka := strings.Split(string(*MyPrivateEDKey), "ed25519")
		copy(pvk[0:64], pvka[2][40:104])
		encoded = ed25519.Sign(pvk, hashed[:])
	}
	//fmt.Println("checking signature:",Verify(contents,encoded,string(Self.Said)))
	return encoded, err
}

func Verify(contents []byte, encoded []byte, pubkey string) (err error) {

	var block *pem.Block
	var o []byte
	var verifyer ssh.PublicKey

	hashed := sha256.Sum256(contents)
	pka := strings.Split(pubkey, " ")
	//fmt.Println("Verifying with",pka[0])
	if pka[0] == "ssh-rsa" {
		pubKeyString := s2r.Translate(string(pubkey))
		if block, o = pem.Decode([]byte(pubKeyString)); o == nil {
			err = errors.New("failed to parse PEM block containing the public key")
		} else {
			rpk, err2 := x509.ParsePKIXPublicKey(block.Bytes)
			if err2 != nil {
				err = err2
			} else {
				err = rsa.VerifyPKCS1v15(rpk.(*rsa.PublicKey), crypto.SHA256, hashed[:], encoded)
			}

		}
	} else if pka[0] == "ssh-ed25519" {
		if verifyer, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubkey)); err == nil {
			vfb := verifyer.Marshal()
			if !ed25519.Verify(vfb[len(vfb)-32:], hashed[:], encoded) {
				err = errors.New("failure to verify ed25519 signature")
			}
		}

	} else {
		err = errors.New("can't handle verifying with " + pka[0] + " public keys yet.")
	}
	return err
}
