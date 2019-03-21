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
	"errors"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/binary"
	//	"flag"
	//	"github.com/io-core/Attest/s2r"
	"io/ioutil"
	"os"
	//	"path/filepath"
	"strings"
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

type Shah [32]byte // In this code if a variable name is two letters, it contains a Shah

type Ident struct {
	Pubkey  []byte
	Id      Shah // Sha256(Pubkey in "<keytype> <base64-encoded-key> Id" form) represents this identity
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
var Self Ident
var MyNameStmt Stmt
var MyNameClaim Claim
var MyPrivateKey *rsa.PrivateKey
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

func getKeys(pkfn, bkfn string) (key *rsa.PrivateKey, pk, bk []byte, err error) {	
	var bkt []byte
	if pk, err = ioutil.ReadFile(pkfn); err == nil { 
		if bkt, err = ioutil.ReadFile(bkfn); err == nil {
			
			bka:= strings.Split(string(bkt)," ")
			l:=len(bka)
			if l<3 {
				err = errors.New("too few fields in public key file")
			}else{
				if l>3{  // count from end because options may contain quoted spaces
					bk=[]byte(bka[l-2]+" "+bka[l-3]+" Id")
				}else{
					bk=[]byte(bka[0]+" "+bka[1]+" Id")
				}
			}
			privPem, _ := pem.Decode(pk)
			privPemBytes := privPem.Bytes
			key, err = x509.ParsePKCS1PrivateKey(privPemBytes)
		}
	}
	return key, pk, bk, err
}

func MakeClaim( affirm bool, count uint64, by, er, ee, st Shah) (c Claim, err error){
	
        var sig []byte

        c.Affirm = affirm
        c.C = count
        c.By = by
        c.Er = er
        c.Ee = ee
        c.St = st


	abuf := make([]byte, 8)
	abuf[0]=1  //version 1 of the claim packing format for signatures... bytes 1-6 are undefined
	if affirm {
		abuf[7]=0
	}else{
		abuf[7]=255
	}

	cbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(cbuf, c.C)
	

	if sig, err = Sign( append(abuf, 
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

func WellFormedClaim( c Claim) bool {

	return true
}

func recall( pfn, bfn, mfn, n string, init, force bool) (err error) {
	//var self Ident

        if _, mferr := os.Stat(mfn); mferr != nil {
                if ! init { 
                        err = errors.New("The memory file does not exist and initialization was not requested.")
                } else {
                        // initializing persistent store
			
			var pk, bk []byte
			if MyPrivateKey, pk, bk, err = getKeys(pfn, bfn); err == nil {	
				fmt.Println(":MYPRIVATE:")
				fmt.Println(string(pk))
                                fmt.Println(":MYPUBLIC:")
                                fmt.Println(string(bk))
				Self.Pubkey = bk
                                fmt.Println(":MYID:")				
                                Me = sha256.Sum256(Self.Pubkey)
				Self.Id = Me
                                fmt.Println(base64.StdEncoding.EncodeToString(Me[:]))
				MyNameStmt.Said = []byte(n)
				MyNameStmt.Sd = sha256.Sum256(MyNameStmt.Said)
				if MyNameClaim, err = MakeClaim( true, 0, Me, Me, Me, MyNameStmt.Sd ); err == nil {
					fmt.Println(":MYNAMECLAIM:")
					fmt.Println(MyNameClaim.Affirm)
					fmt.Println(MyNameClaim.C)
					fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.By[:]))
					fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.Er[:]))
                                        fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.Ee[:]))
                                        fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.St[:]))
                                        fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.Sig))
                                        fmt.Println(base64.StdEncoding.EncodeToString(MyNameClaim.Cl[:]))
				}
			}
                }
        } else {
                if init {
			if force {
				// re-initializing persistent store
                        	if MyPrivateKey, _, _, err = getKeys(pfn, bfn); err == nil {
                        	}

			}else{
                        	err = errors.New("The memory file already exists and force was not requested.")
			}
                } else {
                        // loading from persistent store
                }
        }

	return err
}

func persist( mfn string ) (err error) {

	return err
}

func Startup(pfn, bfn, mfn, n string, init, force, debug bool) (err error) {
	if debug {
		fmt.Println("loading keys identities and claims...")
		fmt.Println(pfn, bfn, mfn, n, Me, Bands, All, Stmts, Claims)
	}
	
	if err = recall(pfn, bfn, mfn, n, init, force); err != nil {
			
		
	
		if debug {
			fmt.Println("loaded!")
		}
	}
	
	return err
}

func Shutdown(pfn, bfn, mfn string, debug bool) (err error) {
	if debug {
		fmt.Println("storing identities and claims...")

	}
	
	if err = persist(mfn); err != nil {

		if debug {
			fmt.Println("stored!")
		}
	}
	return err
}

func Sign(contents []byte) (encoded []byte, err error) {
	hashed := sha256.Sum256(contents)

	signature := []byte{}
	if signature, err = rsa.SignPKCS1v15(rand.Reader, MyPrivateKey, crypto.SHA256, hashed[:]); err == nil {

		encoded = signature //base64.StdEncoding.EncodeToString(signature)
	
		
	}
	return encoded, err
}

