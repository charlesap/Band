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

import "fmt"
import "flag"
import "os"
import "github.com/charlesap/Inband"

func main(){
	vPtr := flag.Bool("version",false, "Print the version of bandit and exit")
        dPtr := flag.Bool("debug",false, "Print debug information while running")
        iPtr := flag.Bool("init",false, "Initialize the history")
        fPtr := flag.Bool("force",false, "Force initialization (re-initialize) the history")


	pkeyPtr := flag.String("p", os.Getenv("HOME")+"/.ssh/id_rsa", "path to rsa private key file")
	bkeyPtr := flag.String("b", os.Getenv("HOME")+"/.ssh/id_rsa.pub", "path to rsa public key file")
        bandPtr := flag.String("h", os.Getenv("HOME")+"/.ssh/band_memory", "path to band_memory file")
  flag.Parse()
  if *vPtr {
    fmt.Println("bandit version 0.0.1")
    os.Exit(0)
  }
  Setup()
  inband.Load(*pkeyPtr,*bkeyPtr,*bandPtr,*iPtr,*fPtr,*dPtr)
  Run()
  inband.Store(*pkeyPtr,*bkeyPtr,*bandPtr,*dPtr)
}


func Setup()  {
 fmt.Println( "Setup")
}

func Help(debug bool)  {
 fmt.Println( "Help")

}

func Run()  {
 fmt.Println( "running")

 fmt.Println( "done")

}
