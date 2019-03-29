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
)

func main() {
	vPtr := flag.Bool("version", false, "Print the version of bandit and exit")
	dPtr := flag.Bool("debug", false, "Print debug information while running")
	iPtr := flag.Bool("init", false, "Initialize the history")
	fPtr := flag.Bool("force", false, "Force initialization (re-initialize) the history")

	tkeyPtr := flag.String("t", "rsa", "type of initialization key pair to look for, e.g. 'rsa' or 'ed25519' or 'ssb'")
	pkeyPtr := flag.String("p", os.Getenv("HOME")+"/.ssh/", "path to initialization key files")

	bandPtr := flag.String("h", os.Getenv("HOME")+"/.ssh/band_memory", "path to band_memory file")
	namePtr := flag.String("n", "Anonymous", "name for a new identity when initializing the history")
	flag.Parse()
	if *vPtr {
		fmt.Println("bandit version 0.0.1")
		os.Exit(0)
	}
	Setup()
	err := inband.Startup(*tkeyPtr, *pkeyPtr, *bandPtr, *namePtr, *iPtr, *fPtr, *dPtr)
	if err == nil {
		Run(*dPtr)
		err = inband.Shutdown(*tkeyPtr, *pkeyPtr, *bandPtr, *dPtr)
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
	
        for id,c := range inband.Idents {
		s,x := inband.Stmts[c.St]
		if x {
			fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))

		}else{
			fmt.Println("Couldn't match a name to an identity. Sorry...")
		}
        }

}

func What(debug bool) {
        
        for id,b := range inband.Bands {
                s,x := inband.Stmts[b.St]
                if x { 
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
                        
                }else{  
                        fmt.Println("Couldn't match a name to an identity. Sorry...")
                }       
        }       
        
}

func New(g,n string, debug bool) {

}       

func Show(s string, debug bool) {
	var id inband.Shah
	if s == "me" {
		id = inband.Yo
	}else{
	}
        c,x := inband.Idents[id]
	if x {
                s,x := inband.Stmts[c.St]
                if x {
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))
                }else{
                        fmt.Println("Couldn't match a name to an identity. Sorry...")
                }
                s,x = inband.Stmts[c.By]
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
                s,x := inband.Stmts[c.St]
                if x { 
                        n=string(s.Said)
		}
		if n == f {
                        fmt.Println(string(s.Said))
                        fmt.Println(base64.StdEncoding.EncodeToString(id[:]))

                	s,x = inband.Stmts[c.By]
                	if x {
                	        fmt.Println(string(s.Said))
                	}else{  
                        	fmt.Println("Couldn't match a public key to an identity. Sorry...")
                	}       
                }
                
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

		if strings.Compare("exit", words[0]) == 0 {
			fmt.Println("Goodbye.")
			done = true
		}

	}

	

}
