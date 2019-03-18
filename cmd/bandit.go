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
  vptr := flag.Bool("version",false, "Print the version of bandit and exit")
  iptr := flag.String("in","-", "Input File")
  optr := flag.String("out","-", "Output File")
  cptr := flag.String("config","", "Config File")
  eptr := flag.String("encoders","ASE", "Encoders")
  fptr := flag.String("format","csv", "Format")
  flag.Parse()
  if *vptr {
    fmt.Println("bandit version 0.0.1")
    os.Exit(0)
  }
  Setup(*iptr,*optr,*cptr,*eptr,*fptr)
  inband.Initialize(true)
  Run("input","params","state","output")
}


func Setup(i string,o string,c string,e string,f string)  ( string, string, string, string)  {
 var inf string
 var param string
 var state string
 var outf string
 if c != "" {
    inf,param,state,outf = LoadConfig(c) //    call LoadConfig with c giving inf,param,state,outf
 }else{
    inf = i
    param = o
    state = e
    outf = f
 }
 fmt.Println( "Setup")
 return  inf,param,state,outf

}

func LoadConfig(c string)  ( string, string, string, string)  {
 var i string
 var o string
 var e string
 var f string
 fmt.Println( "Loadconfig")
 i = "-"
 o = "-"
 e = "-"
 f = "-"
 return  i,o,e,f

}

func Help(debug bool)  {
 fmt.Println( "Help")

}

func Run(inf string,param string,state string,outf string)  {
 fmt.Println( "running")
// MERGE
 fmt.Println( "done")

}
