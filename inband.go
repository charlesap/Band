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
	"fmt"
//	"crypto"
//	"crypto/rand"
	"crypto/rsa"
//	"crypto/sha256"
	"crypto/x509"
//	"encoding/base64"
	"encoding/pem"
//	"flag"
//	"github.com/io-core/Attest/s2r"
	"io/ioutil"
	"os"
//	"path/filepath"
	"strings"
//	"time"
)

// DESIGN

// An Id is formed by creating a private/public key pair and taking the shah of a
// cert  with the private key.

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





type Shah [16]byte // In this code if a variable name is two letters, it contains a Shah

type Ident struct {
	Privkey []byte
	Pubkey  []byte
	Ps      Shah
	Id      Shah // Represents this identity
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
	C      int // Increment for superceding claims
	By     Shah
	Er     Shah
	Ee     Shah
	St     Shah
	Cl     Shah // Represents this claim
}

type ICCC struct {
	I Ident
	B CChain
	R CChain
	E CChain
}

var Me Shah
var Bands []Shah
var All map[Shah]ICCC = make(map[Shah]ICCC)  // individual/band, By chain, Er chain, Ee chain for this Id
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

func getKeys(pkfn, bkfn string) (*rsa.PrivateKey, string, error) {
	err := error(nil)
	bks := ""
	var parsedKey *rsa.PrivateKey
        if _, err1 := os.Stat(pkfn); err1 != nil {
		err = err1
        }else{
		if _, err2 := os.Stat(bkfn); err2 != nil {
                	err = err2
		}else{
	        	pk, _ := ioutil.ReadFile(pkfn)
	        	bk, _ := ioutil.ReadFile(bkfn)
			bks = strings.TrimSpace(string(bk))
			privPem, _ := pem.Decode(pk)
			privPemBytes := privPem.Bytes
			parsedKey, _ = x509.ParsePKCS1PrivateKey(privPemBytes)
		}
	}
	return parsedKey, bks, err
}

func Load(pf, bf, mf string, init, force, debug bool) error {
	if debug {
		fmt.Println("loading keys identities and claims...")
		fmt.Println(pf, bf, mf, Me, Bands, All, Stmts, Claims)
	}
	_,_,_=getKeys(pf,bf)

        if _, err := os.Stat(mf); err != nil {
		if init{
		}else{
                        fmt.Println("The memory file does not exist and initialization was not requested.")
			os.Exit(1)
		}
	}else{
		if init{
			fmt.Println("The memory file already exists and force was not requested.")
			os.Exit(1)
		}else{
		}
	}

	if debug {
		fmt.Println("loaded!")
	}
	return error(nil)
}

func Store(pf, bf, hf string, debug bool) {
        if debug {
                fmt.Println("storing identities and claims...")
                
        }
    

        if debug {
                fmt.Println("stored!")
        }
}


