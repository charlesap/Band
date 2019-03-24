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
	"golang.org/x/crypto/ed25519" // golang.org/x/crypto
	"encoding/hex"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	//	"flag"
	//	"github.com/io-core/Attest/s2r"
	"io/ioutil"
	"os"
	//	"path/filepath"
	"strings"
	"strconv"
	//"time"
)

// DESIGN

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

type Ident struct {
	Pubkey []byte
	Id     Shah // Sha256(Pubkey in "<keytype> <base64-encoded-key> Id" form) represents this identity
}

type CChain struct {
	Next *CChain
	This *Claim
}

type Stmt struct {
	Said []byte
	Sd   Shah // Represents this statement
}

type Claim struct {
	Affirm bool
	C      uint64 // Increment for superceding claims
	By     Shah
	Er     Shah
	Ee     Shah
	St     Shah
	Sig    []byte
	Cl     Shah // Represents this claim
}

type ICCC struct {
	I Ident
	B CChain
	R CChain
	E CChain
}

var Me Shah
var Yo Shah
var Self Ident
var MyNameStmt Stmt
var MyNameClaim Claim
var MyPrivateRSAKey *rsa.PrivateKey
var MyPrivateKeyType string
var MyPrivateCert []byte
var Bands []Shah
var All map[Shah]ICCC = make(map[Shah]ICCC) // individual/band, By chain, Er chain, Ee chain for this Id
var Topics map[Shah]CChain = make(map[Shah]CChain)
var Stmts map[Shah]Stmt = make(map[Shah]Stmt)
var Claims map[Shah]Claim = make(map[Shah]Claim)

func (b Shah) Consider(c Claim) {
}

func (b Shah) Moot(debug bool) {
	if debug {
		i := All[b]
		fmt.Println("Mooting in", i.I.Is())
	}
}

func (i Ident) Visit(debug bool) {
	if debug {
		fmt.Println("Visiting", i.Is())
	}
}

func (i Ident) Is() string {
	//return string(Stmts[i.St].Said)
	return "somebody"
}

func getKeys(typ, pkfn string) (key *rsa.PrivateKey, pkb, bkb []byte, err error) {
	var bkt []byte
        if typ == "rsa" {
		if pkb, err = ioutil.ReadFile(pkfn+"/id_rsa"); err == nil {
			if bkt, err = ioutil.ReadFile(pkfn+"/id_rsa.pub"); err == nil {

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
				key, err = x509.ParsePKCS1PrivateKey(privPemBytes)
			}
		}
	}else{
		err = errors.New("Don't know how to load "+typ+" keys on init.")
	}
	
	return key, pkb, bkb, err
}

func MakeClaim(affirm bool, count uint64, by, er, ee, st Shah) (c Claim, err error) {

	var sig []byte

	c.Affirm = affirm
	c.C = count
	c.By = by
	c.Er = er
	c.Ee = ee
	c.St = st

	abuf := make([]byte, 8)
	abuf[0] = 1 //version 1 of the claim packing format for signatures... bytes 1-6 should be zero
	if affirm {
		abuf[7] = 0
	} else {
		abuf[7] = 255
	}

	cbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(cbuf, c.C)

	if sig, err = Sign(append(abuf,
		append(cbuf,
			append(c.By[:],
				append(c.Er[:],
					append(c.Ee[:],
						c.St[:]...)...)...)...)...)); err == nil {
		c.Sig = sig
		c.Cl = sha256.Sum256(c.Sig)
	}
	return c, err
}

func Untampered(c Claim) bool {

	return true
}

func xcheck(e error) {
	if e != nil {
		panic(e)
	}
}

func claim2string(h string, c Claim) string {
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



func initFromRSA(typ, pfn, mfn, n string) (err error) {
	var bkb []byte
	MyPrivateKeyType = typ
	if MyPrivateRSAKey, MyPrivateCert, bkb, err = getKeys(typ, pfn); err == nil {
		fmt.Println("Initializing from SSH keys")		
		Self.Pubkey = bkb
		Me = sha256.Sum256(Self.Pubkey)
		Self.Id = Me
		MyNameStmt.Said = []byte(n)
		MyNameStmt.Sd = sha256.Sum256(MyNameStmt.Said)
		Stmts[MyNameStmt.Sd] = MyNameStmt
		if MyNameClaim, err = MakeClaim(true, 0, Me, Me, Me, MyNameStmt.Sd); err == nil {
			Yo = MyNameClaim.Cl
			Claims[Yo] = MyNameClaim
			err = persist(mfn)
		}
	}

	return err
}

func recallFromFile(mfn string) (err error) {
	var b,x,pkb []byte
	//var self Ident
	
	
        if b, err = ioutil.ReadFile(mfn); err == nil {
        	a:=strings.Split(string(b),"\n:")
		for _,e := range a {
		    l:=strings.Split(e,":\n")
		    if err == nil {
			if l[0]==":MYPRIVATE" {				
                                MyPrivateCert = []byte(l[1])
                        	privPem, _ := pem.Decode(MyPrivateCert)
                        	privPemBytes := privPem.Bytes
                        	MyPrivateRSAKey, err = x509.ParsePKCS1PrivateKey(privPemBytes)

			}else if l[0]=="MYPUBLIC" {
                                pkb = []byte(l[1])
                        }else if l[0]=="MYID" {
                                if x , err = base64.StdEncoding.DecodeString(l[1]); err == nil {
					copy(Me[:],x)
					
				}
                        }else if l[0]=="MYNM" {            
                                if x , err = base64.StdEncoding.DecodeString(l[1]); err == nil {
					copy(Yo[:],x)
				}
                        }else if l[0]=="CLAIM" {
				c := new(Claim)
                                if len(l)>8 {
                                        var txt []byte
					if l[1] == "true" {
						c.Affirm = true
					}else{
						c.Affirm = false
					}
					count:=0
					if count, err = strconv.Atoi(l[2]); err == nil {
						c.C = uint64(count) 
					}
                                        if x , err = base64.StdEncoding.DecodeString(l[3]); err == nil {
                                                copy(c.By[:],x)
                                        }
                                        if x , err = base64.StdEncoding.DecodeString(l[4]); err == nil {
                                                copy(c.Er[:],x)
                                        }
                                        if x , err = base64.StdEncoding.DecodeString(l[5]); err == nil {
                                                copy(c.Ee[:],x)
                                        }
                                        if x , err = base64.StdEncoding.DecodeString(l[6]); err == nil {
                                                copy(c.St[:],x)
                                        }
                                        if txt , err = base64.StdEncoding.DecodeString(l[7]); err == nil {
                                                c.Sig=txt
                                        }
                                        if x , err = base64.StdEncoding.DecodeString(l[8]); err == nil {
                                                copy(c.Cl[:],x)
                                        }
                                }
                                Claims[c.Cl]=*c
                        }else if l[0]=="STMT" {
				
                                var txt []byte
				var xb Shah
				ll:=strings.Split(l[1],"\n")
				if len(ll)>1 {
					
                                	if txt , err = base64.StdEncoding.DecodeString(ll[0]); err == nil {
                                	        
                                        	if x , err = base64.StdEncoding.DecodeString(ll[1]); err == nil {
                                                	copy(xb[:],x)
						}
                                        }
				}
				fmt.Println(base64.StdEncoding.EncodeToString(xb[:]))
				Stmts[xb]=Stmt{txt,xb}
			}
		    }
		}
		fmt.Println(Stmts)
		//Self = self
		Self.Id = Me
		Self.Pubkey = pkb
		MyNameStmt = Stmts[Yo]
		//MyNameClaim = Claims[Yo]
	}
	return err

}

func recall(typ, pfn, mfn, n string, init, force bool) (err error) {
	//var self Ident

	if _, mferr := os.Stat(mfn); mferr != nil {
		if !init {
			err = errors.New("The memory file does not exist and initialization was not requested.")
		} else {
			// initializing persistent store
			err = initFromRSA(typ, pfn, mfn, n)
		}
	} else {
		if init {
			if force {
				// re-initializing persistent store
				err = initFromRSA(typ, pfn, mfn, n)
			} else {
				err = errors.New("The memory file already exists and force was not requested.")
			}
		} else {
			// loading from persistent store
		
			recallFromFile(mfn)
			fmt.Println("    Self.Pubkey:",string(Self.Pubkey))
                        fmt.Println("        Self.Id:",base64.StdEncoding.EncodeToString(Self.Id[:]))
			fmt.Println("             Me:",base64.StdEncoding.EncodeToString(Me[:]))
                        fmt.Println("             Yo:",base64.StdEncoding.EncodeToString(Yo[:]))
                        fmt.Println("MyNameStmt.Said:",string(MyNameStmt.Said))
                        fmt.Println("  MyNameStmt.Sd:",base64.StdEncoding.EncodeToString(MyNameStmt.Sd[:]))
 		}
	}

	return err
}

func persist(mfn string) (err error) {
	f, err := os.Create(mfn)
	defer f.Close()
	if err == nil {
		
		_, err = f.WriteString(":MYPRIVATE:\n")
	}
	if err == nil {
		_, err = f.WriteString(string(MyPrivateCert) + "\n")
	}
	if err == nil {
		_, err = f.WriteString(":MYPUBLIC:\n")
	}
	if err == nil {
		_, err = f.WriteString(string(Self.Pubkey) + "\n")
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
	if err == nil {
		for _, c := range Claims {
			if err == nil {
				_, err = f.WriteString(claim2string(":CLAIM:", c))
			}
		}
	}
	if err == nil {
		for _, s := range Stmts {
			if err == nil {
				_, err = f.WriteString(stmt2string(":STMT:", s))
			}
		}
	}
	return err
}

func Startup(typ, pfn, mfn, n string, init, force, debug bool) (err error) {
	if debug {
		fmt.Println("loading keys identities and claims...")
		fmt.Println(typ, pfn, mfn, n, Me, Bands, All, Stmts, Claims)
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
			encoded = signature //base64.StdEncoding.EncodeToString(signature)
		}
	}else{

	


	    priv := "e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d"
	    pub := "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548"
	    sig := "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08"
	    // d := hex.EncodeToString([]byte(priv))
	    privb, _ := hex.DecodeString(priv)
	    pvk := ed25519.PrivateKey(privb)
	    buffer := []byte("4:salt6:foobar3:seqi1e1:v12:Hello World!")
	    sigb := ed25519.Sign(pvk, buffer)
	    pubb, _ := hex.DecodeString(pub)
	    sigb2, _ := hex.DecodeString(sig)

	    if 1==2 { fmt.Println(priv,pub,sig,privb,pvk,buffer,sigb,pubb,sigb2)}

	}

	return encoded, err
}
