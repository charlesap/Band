//  ----------------------------------------------------------------------
//  band implementation and framework for stateless distributed group identity
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

package main

import (
	"fmt"
	"flag"
	"os"
	"bufio"
	"strings"
	"encoding/base64"
	"github.com/charlesap/Inband"
	"github.com/mndrix/golog"
)

func main() {
	vPtr := flag.Bool("version", false, "Print the version of bandit and exit")
	dPtr := flag.Bool("debug", false, "Print debug information while running")
	iPtr := flag.Bool("init", false, "Initialize the history")
	fPtr := flag.Bool("force", false, "Force initialization (re-initialize) the history")

	
	pkeyPtr := flag.String("p", os.Getenv("HOME")+"/.ssh/", "path to initialization key files")

	bandPtr := flag.String("h", os.Getenv("HOME")+"/.ssh/band_memory", "path to band_memory file")
	namePtr := flag.String("n", "Anonymous", "name for a new identity when initializing the history")
	flag.Parse()
	if *vPtr {
		fmt.Println("bandit version 0.0.1")
		os.Exit(0)
	}
	Setup()
	err := inband.Startup( *pkeyPtr, *bandPtr, *namePtr, *iPtr, *fPtr, *dPtr)
	if err == nil {
		Run(*dPtr)
		err = inband.Shutdown( *pkeyPtr, *bandPtr, *dPtr)
	}
	if err != nil {
		fmt.Println(err)
	}
}

func Setup() {
	fmt.Println("Setup")
}

func Help(debug bool) {
	fmt.Println("Bandit Shell Commands:")
        fmt.Println("   exit               - Exit the bandit shell.")
        fmt.Println("   who                - print out identities.")
        fmt.Println("   what               - print out groups.")
        fmt.Println("   show me|<identity> - print out an identity.")
        fmt.Println("   find <name>        - find the identity of a name.")
        fmt.Println("   new band <name>   - create a new band.")


}

func Who(debug bool) {
	fmt.Println("Number of idents:",len(inband.Idents))
        for id,c := range inband.Idents {
		s,x := inband.Stmts[c.Fld[3].Sd]
		if x {
			fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))

		}else{
			fmt.Println("Couldn't match a name to an identity. Sorry...")
		}
        }

}

func Why(debug bool) {
        fmt.Println("Number of Names:",len(inband.Names))
        for id,c := range inband.Names {
                s,x := inband.Stmts[c.Fld[3].Sd]
                if x {
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
         
                }else{
                        fmt.Println("Couldn't match a name to an identity. Sorry...")
                }
        }

}



func What(debug bool) {
        fmt.Println("Number of bands:",len(inband.Bands))        
        for id,b := range inband.Bands {
                s,x := inband.Stmts[b.Fld[2].Sd]
                if x { 
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
                        
                }else{  
                        fmt.Println("Couldn't match a name to an band. Sorry...")
                }       
        }       
        
}

func How(debug bool) {
        fmt.Println("Founders of bands, names:",len(inband.Founds),len(inband.Names))
        for id,b := range inband.Founds {
                c,x := inband.Idents[b.Fld[1].Sd]
                if x {
                  t,y := inband.Names[c.Fld[3].Sd]
                  if y {

                        fmt.Println(string(t.Fld[3].Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
		  }else{
                        fmt.Println("1:Couldn't match a name to a founder. Sorry...")
		  }
                }else{
                        fmt.Println("2:Couldn't match a claim to a founder. Sorry...")
                }
	    
        }

}



func New(g,n string, debug bool) {
	inband.NewBand(n)
}       

func Show(s string, debug bool) {
	var id inband.Shah
	if s == "me" {
		id = inband.NmP.Sd
	}else{
	}
        c,x := inband.Idents[id]
	if x {
                s,x := inband.Stmts[c.Fld[3].Sd]
                if x {
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
                }else{
                        fmt.Println("Couldn't match a name to an identity. Sorry...")
                }
                s,x = inband.Stmts[c.Fld[0].Sd]
                if x {
                        fmt.Println(string(s.Said))
                }else{
                        fmt.Println("Couldn't match a public key to an identity. Sorry...")
                }


	}else{
		fmt.Println(s,"not found.")
	}
        

}

func Find(f string, debug bool) {
        for id, c := range inband.Idents { 
		n:=""
                s,x := inband.Stmts[c.Fld[3].Sd]
                if x { 
                        n=string(s.Said)
		}
		if n == f {
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))

                	s,x = inband.Stmts[c.Fld[0].Sd]
                	if x {
                	        fmt.Println(string(s.Said))
                	}else{  
                        	fmt.Println("Couldn't match a public key to an identity. Sorry...")
                	}       
                }
                
        }       


}


const rules = `

 * i / i "name"  t    -> names i t.
 * i / i "follow" j   -> follows i j.
 * i / i "block" j    -> blocks i j.
 * i / i "friend" j   -> friends i j.
 ^ b / b "band"  t    -> bands b t.
 ^ b / i "found" b    -> founder b i.
 > i / j "accept" b   -> accepting b i j. 
 > i / j "reject" b   -> rejecting b i j.
 > i / b "shun" j     -> shunning b i j.
 > i / b "defend" j   -> defending b i j.
 > i / j t b          -> claiming b i t j. 
 > i / i "assoc" b    -> associating i b.
 > i / i "aka" j      -> aka i j.
 > i / j "nic" k      -> nicnames i j k.
 > i / i "insist" t   ~
 > i / i "deny" t     ~
 * i / i "email" t    -> emails i t.
 * i / b "bmail" t    -> bmails i t b.
 * i / i "phone" t    -> phones i t.
 * i / i "address" t  -> addresses i t.
 * i / i "geohash" t  -> geohashes i t.


foaf I J = friends I X & friends X J.

connected I J = friends I J 
              | friends I X & connected X J.

member B I = founder B I 
	   | associating I B & count(accepting B _ I) > count(rejecting B _ I).

shunned B I = count(shunning B _ I) > count(defending B _ I).

speaker B I = member B I & max(claiming B _ "speaker" I,I)

member "Bob" "Thunder Cats"?
speaker "Nancy" "House"?


`

func Interp(debug bool){

	m := golog.NewMachine().Consult(`

    father(john).
    father(jacob).

    mother(sue).

    parent(X) :-
        father(X).
    parent(X) :-
        mother(X).

	`)
	if m.CanProve(`father(john).`) {
	    fmt.Printf("john is a father\n")
	}

	solutions := m.ProveAll(`parent(X).`)
	for _, solution := range solutions {
	    fmt.Printf("%s is a parent\n", solution.ByName_("X"))
	}

}

func Run(debug bool) {
	
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Bandit Shell")
	done := false

	for !done {
		fmt.Print("-> ")
		line, _ := reader.ReadString('\n')
		line = strings.Replace(line, "\n", "", -1)
		words := strings.Split(line," ")

                if strings.Compare("help", words[0]) == 0 {
                        Help(debug)
                }       

                if strings.Compare("find", words[0]) == 0 {
                        if len(words)>1{
                                Find( words[1], debug)
                        }else{
                                fmt.Println("   Need a name to look for")
                        }
                }

                if strings.Compare("show", words[0]) == 0 {
			if len(words)>1{
                        	Show( words[1], debug)
			}else{
				fmt.Println("   Need 'me' or an identity string")
			}
                }       

                if strings.Compare("new", words[0]) == 0 {
                        if len(words)>2{
                                New( words[1], words[2], debug)
                        }else{
                                fmt.Println("   Need 'band' and a band name")
                        }
                }
                if strings.Compare("who", words[0]) == 0 {
                        Who(debug)
                }       

                if strings.Compare("what", words[0]) == 0 {
                        What(debug)
                }

                if strings.Compare("how", words[0]) == 0 {
                        How(debug)
                }

                if strings.Compare("why", words[0]) == 0 {
                        Why(debug)
                }

		if strings.Compare("exit", words[0]) == 0 {
			fmt.Println("Goodbye.")
			done = true
		}

	}

	

}
