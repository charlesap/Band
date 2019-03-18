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

package inband

import "fmt"

const (
  ANNOUNCE = iota   //   key:value, e.g. found a band of individuals
  SPONSOR = iota    // sponsor the membership of an individual in a band
  REJECT = iota     // reject the membership of an individual in a band
  SUPPORT = iota    // support an individual for a role
  OPPOSE = iota     // oppose an individual for a rola
  SUSTAIN = iota    // sustain a role in a band
  DETRACT = iota    // detract (oppose sustaining) a role in a band
  AFFIRM = iota     // affirm a name for an individual in a band
  DISPUTE = iota    // dispute (oppose affirming) a name for an individual in a band
)

type Band struct {
  Name string
  Hash []byte
}

type Self struct {
  Privkey []byte
  Pubkey []byte
  Hash []byte
  Name string
}

type Other struct {
  Pubkey []byte
  Hash []byte
  Name string
}

type Claim struct {
  Typ int
  Key []byte
  Val []byte
}



func (o Other) Meetup(debug bool){
  if debug {
    fmt.Println( "Meeting with",o.Name)
  }
}

func (b Band) GetName(debug bool){
  if debug {
    fmt.Println( "Band name:",b.Name)
  }
}


func Initialize(debug bool)  {
  if debug{
    fmt.Println( "initializing-internal-store")
    fmt.Println( "ready!")
  }
}
