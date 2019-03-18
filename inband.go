//  ----------------------------------------------------------------------
//  band implementation and framework for stateless distributed group identity
//  copyright 2019 and distributed under the MIT license 
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
