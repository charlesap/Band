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

import (
	"testing"
	"os"
	//"fmt"
)
func Test_reporting_nonexistant_keys_and_bandmemory(t *testing.T) {
	pkey := "/badpublickeyfilename"
	ktype := "rsa"
	band := "/badbandmemoryfilename"
	name := "Anonymous"
	i := true
	f := false
	d := false
	want := "open /badpublickeyfilename/id_rsa: no such file or directory"
	if got := Startup(ktype, pkey, band, name, i, f, d); got != nil && got.Error() != want {
		t.Errorf("Load() = %q, want %q", got.Error(), want)
	}else if got == nil{
                t.Errorf("Load() = %q, want %q", error(nil), want)
	}
}

func Test_Loading_keys(t *testing.T) {
	pkey := os.Getenv("HOME")+"/.ssh"
	band := os.Getenv("HOME")+"/.ssh/band_memory_test"
        if got := Startup("foo", pkey, band, "Anonymous", true, true, false); got.Error() != "Don't know how to load foo keys on init." {
                t.Errorf("Startup( /unknown key type/ ) = %q, expected error(nil)", got.Error())
        }       
        if got := Startup("rsa", pkey, band, "Anonymous", true, true, false); got != nil {
                t.Errorf("Startup( /rsa/ ) = %q, expected error(nil)", got.Error())
        }

        want := error(nil)
        if got := recallFromFile(band); got != want {
                t.Errorf("recallFromFile( /rsa/ ) = %q, want %q", got, want)
        }

        if got := Startup("ed25519", pkey, band, "Anonymous", true, true, false); got != nil {
                t.Errorf("Startup( /ed25519/ ) = %q, expected error(nil)", got.Error())
        }       

        if got := recallFromFile(band); got != want {
                t.Errorf("recallFromFile( /ed25519/ ) = %q, want %q", got, want)
        }

        pkey = os.Getenv("HOME")+"/.ssb"
        if got := Startup("ssb", pkey, band, "Anonymous", true, true, false); got.Error() != "ssb not implemented yet." {
                t.Errorf("Startup( /ssb/ ) = %q, expected error(nil)", got.Error())
        }

        //if got := recallFromFile(band); got != want {
        //        t.Errorf("recallFromFile( /ssb/ ) = %q, want %q", got, want)
        //}
}
		

