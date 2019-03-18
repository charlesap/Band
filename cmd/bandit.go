//  ----------------------------------------------------------------------
//  band implementation and framework for stateless distributed group identity
//  copyright 2019 and distributed under the MIT license
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
