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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
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
// NAME:      claimaint says claimant 'NAME' '<name>'   ... may be many, a.k.a
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

// Language and Culture -- syntax of statements vs. behavioral impact of transmitted statements

type Shah [32]byte // In this code if a variable name is two letters, it contains a Shah

type Stmt struct {
	Said []byte
	Sd   Shah // Represents this statement
}

type Claim struct {
	Affirm bool
	C      uint64 // Increment for superceding claims
	ByP    *Stmt
	ErP    *Stmt
	EeP    *Stmt
	StP    *Stmt
	Sig    []byte
	Cl     Shah // Represents this claim
}

var MeP *Stmt
var NmP *Stmt

var MyPrivateCert []byte
var MyPrivateKey *ed25519.PrivateKey

var Stmts map[Shah]*Stmt
var Claims map[Shah]*Claim

var NAME, BAND, FOUND *Stmt

var Idents map[Shah]*Claim // indexed by Shah of pubkey
var Names map[Shah]*Claim  // indexed by shah of name with greatest C
var Bands map[Shah]*Claim
var Founds map[Shah]*Claim

func prepopulate() {
	predef := []string{"name",
		"band",
		"found"}

	for _, v := range predef {
		pd := sha256.Sum256([]byte(v))
		ppd := &Stmt{[]byte(v), pd}
		Stmts[pd] = ppd
		if v=="name" { NAME = ppd }
                if v=="band" { BAND = ppd }
                if v=="foud" { FOUND = ppd }
	}

}

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

func getKeys(pkfn string) (edkey *ed25519.PrivateKey, pkb, bkb []byte, err error) {
	var bkt []byte

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
	return edkey, pkb, bkb, err
}

func MakeClaim(affirm bool, count uint64, pby, per, pee, pst *Stmt, key *ed25519.PrivateKey) (c *Claim, err error) {
	var sig []byte
	var a byte = 0

	By := Stmts[pby.Sd].Sd
	Er := Stmts[per.Sd].Sd
	Ee := Stmts[pee.Sd].Sd
	St := Stmts[pst.Sd].Sd

	if !affirm {
		a = 255
	}
	cbuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(cbuf, count)
	if sig, err = SignAs(append([]byte{1, 0, 0, 0, 0, 0, 0, a},
		append(cbuf,
			append(By[:],
				append(Er[:],
					append(Ee[:],
						St[:]...)...)...)...)...), key, Stmts[Er].Said); err == nil {

		c = &Claim{affirm, count, pby, per, pee, pst, sig, sha256.Sum256(sig)}
	}

	return c, err
}

func Untampered(c *Claim) (ok bool) {

	s, e := Stmts[c.ByP.Sd]
	if !e {
		ok = false
	} else {

		By := Stmts[c.ByP.Sd].Sd
		Er := Stmts[c.ErP.Sd].Sd
		Ee := Stmts[c.EeP.Sd].Sd
		St := Stmts[c.StP.Sd].Sd

		var a byte = 0
		if !c.Affirm {
			a = 255
		}

		cbuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(cbuf, c.C)

		q := append([]byte{1, 0, 0, 0, 0, 0, 0, a},
			append(cbuf,
				append(By[:],
					append(Er[:],
						append(Ee[:],
							St[:]...)...)...)...)...)

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
		base64.StdEncoding.EncodeToString(c.ByP.Sd[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.ErP.Sd[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.EeP.Sd[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.StP.Sd[:]) + "\n" +
		base64.StdEncoding.EncodeToString(c.Sig) + "\n" +
		base64.StdEncoding.EncodeToString(c.Cl[:]) + "\n"
}

func stmt2string(h string, s Stmt) string {
	return fmt.Sprintf(h+"\n") +
		base64.StdEncoding.EncodeToString(s.Said) + "\n" +
		base64.StdEncoding.EncodeToString(s.Sd[:]) + "\n"
}

func NewBand(n string) (err error) {
	var pubk ed25519.PublicKey
	var privk []byte
	var bnc *Claim

	if pubk, privk, err = ed25519.GenerateKey(nil); err == nil {

		s, _ := ssh.NewPublicKey(pubk)
		spk := ssh.MarshalAuthorizedKey(s)

		p := ed25519.PrivateKey(edkey.MarshalED25519PrivateKey(privk))
		it := sha256.Sum256(spk)
		pit := &Stmt{spk, it}
		Stmts[it] = pit

		nm := sha256.Sum256([]byte(n))
		pnm := &Stmt{[]byte(n), nm}
		Stmts[nm] = pnm

		bnc, err = MakeClaim(true, 18446744073709551615, pit, pit, pnm, pit, &p)
		Claims[bnc.Cl] = bnc
		Bands[bnc.Cl] = bnc

		//t := "founder"
		//ft := sha256.Sum256([]byte(t))
		//Stmts[ft] = Stmt{[]byte(t), ft}

		bnc, err = MakeClaim(true, 18446744073709551615, pit, MeP, pit, pit, &p)
		Claims[bnc.Cl] = bnc
		Founds[bnc.Cl] = bnc

	}
	return err
}

func initFromKeys(pfn, mfn, n string) (err error) {
	var bkb []byte
	var mnc *Claim

	if MyPrivateKey, MyPrivateCert, bkb, err = getKeys(pfn); err == nil {

		me := sha256.Sum256(bkb)
		MeP = &Stmt{bkb, me}
		Stmts[me] = MeP
		nm := sha256.Sum256([]byte(n))
		NmP = &Stmt{[]byte(n), nm}
		Stmts[nm] = NmP

		if mnc, err = MakeClaim(true, 0, MeP, MeP, MeP, NmP, MyPrivateKey); err == nil {

			Claims[mnc.Cl] = mnc
			Idents[mnc.Cl] = mnc
			Names[NmP.Sd] = mnc
			err = persist(mfn)
		}
	}

	return err
}

func recallFromFile(mfn string) (err error) {
	var b, x []byte
	var Me, y Shah

	if b, err = ioutil.ReadFile(mfn); err == nil {
		a := strings.Split(string(b), "\n:")
		for _, e := range a {
			l := strings.Split(e, ":\n")
			if err == nil {
				if l[0] == ":MYPRIVATE" {
					MyPrivateCert = []byte(l[1])
					privPem, _ := pem.Decode(MyPrivateCert)
					privPemBytes := privPem.Bytes
					ek := ed25519.PrivateKey(privPemBytes)
					MyPrivateKey = &ek
				} else if l[0] == "MYID" {
					if x, err = base64.StdEncoding.DecodeString(l[1]); err == nil {
						copy(Me[:], x)

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

					Stmts[xb] = &Stmt{txt, xb}
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
							copy(y[:], x)
							c.ByP = Stmts[y]
						}
						if x, err = base64.StdEncoding.DecodeString(ll[3]); err == nil {
							copy(y[:], x)
							c.ErP = Stmts[y]
						}
						if x, err = base64.StdEncoding.DecodeString(ll[4]); err == nil {
							copy(y[:], x)
							c.EeP = Stmts[y]
						}
						if x, err = base64.StdEncoding.DecodeString(ll[5]); err == nil {
							copy(y[:], x)
							c.StP = Stmts[y]
						}
						if txt, err = base64.StdEncoding.DecodeString(ll[6]); err == nil {
							c.Sig = txt
						}
						if x, err = base64.StdEncoding.DecodeString(ll[7]); err == nil {
							copy(c.Cl[:], x)
						}
						if Untampered(c) {
							Claims[c.Cl] = c
							if (c.ByP == c.ErP) && (c.ErP == c.EeP) {
								Idents[c.Cl] = c
							}
							q, got := Names[c.StP.Sd]
							if (!got) || (q.C > c.C) {
								Names[c.StP.Sd] = c
							}
							if (c.ByP == c.ErP) && (c.ByP != c.EeP) && (c.ByP == c.StP) {
								Bands[c.Cl] = c
							}
							if (c.ByP != c.ErP) && (c.ByP == c.EeP) && (c.ByP == c.StP) {
								Founds[c.Cl] = c
							}

						} else {
							err = errors.New("Unable to verify claim " + base64.StdEncoding.EncodeToString(c.Cl[:]))
						}
					} else {

						err = errors.New("too few lines in claim entry")
					}

				}
			}
		}
	}
	return err

}

func recall(pfn, mfn, n string, init, force bool) (err error) {
	Stmts = make(map[Shah]*Stmt)
	Claims = make(map[Shah]*Claim)

	Idents = make(map[Shah]*Claim)
	Names = make(map[Shah]*Claim)
	Bands = make(map[Shah]*Claim)
	Founds = make(map[Shah]*Claim)

	prepopulate()

	if _, mferr := os.Stat(mfn); mferr != nil {
		if !init {
			err = errors.New("The memory file does not exist and initialization was not requested.")
		} else {
			err = initFromKeys(pfn, mfn, n)
		}
	} else {
		if init {
			if force {
				err = initFromKeys(pfn, mfn, n)
			} else {
				err = errors.New("The memory file already exists and force was not requested.")
			}
		} else {
			err = recallFromFile(mfn)
		}
	}
	if err == nil {
		mnm, ok := Stmts[NmP.Sd]
		if !ok {
			err = errors.New("Lost my name")
		}
		fmt.Println("         Hello ", string(mnm.Said))
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
		_, err = f.WriteString(":MYID:\n")
	}
	if err == nil {
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(MeP.Sd[:]) + "\n")
	}
	slf, ok := Stmts[MeP.Sd]
	if !ok {
		err = errors.New("Persist: Lost myself")
	}
	if err == nil {
		_, err = f.WriteString(stmt2string(":STMT:", *slf))
	}
	mnm, ok := Stmts[NmP.Sd]
	if !ok {
		err = errors.New("Persist: Lost my name")
	}
	if err == nil {
		_, err = f.WriteString(stmt2string(":STMT:", *mnm))
	}
	if err == nil {
		for i, s := range Stmts {
			if (i != MeP.Sd) && (i != NmP.Sd) {
				if err == nil {
					_, err = f.WriteString(stmt2string(":STMT:", *s))
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

func Startup(pfn, mfn, n string, init, force, debug bool) (err error) {
	if debug {
		fmt.Println("loading keys identities and claims...")
		//fmt.Println(typ, pfn, mfn, n, Me, Bands, All, Stmts, Claims)
	}

	if err = recall(pfn, mfn, n, init, force); err != nil {

		if debug {
			fmt.Println("loaded!")
		}
	}

	return err
}

func Shutdown(pfn, mfn string, debug bool) (err error) {
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

func Sign(contents []byte) ([]byte, error) {
	return SignAs(contents, MyPrivateKey, Stmts[MeP.Sd].Said)
}

func SignAs(contents []byte, edkey *ed25519.PrivateKey, pbkey []byte) (encoded []byte, err error) {
	hashed := sha256.Sum256(contents)

	pvk := make([]byte, 64)
	pvka := strings.Split(string(*edkey), "ed25519")
	copy(pvk[0:64], pvka[2][40:104])
	encoded = ed25519.Sign(pvk, hashed[:])

	//fmt.Println("checking signature:",Verify(contents,encoded,string(pbkey)))
	return encoded, err
}

func Verify(contents []byte, encoded []byte, pubkey string) (err error) {

	var verifyer ssh.PublicKey

	hashed := sha256.Sum256(contents)
	pka := strings.Split(pubkey, " ")
	if pka[0] == "ssh-ed25519" {
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
