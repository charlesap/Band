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
	bkey := "/badprivatekeyfilename"
	band := "/badbandmemoryfilename"
	i := true
	f := false
	d := false
	want := "open /badpublickeyfilename: no such file or directory"
	if got := Startup(pkey, bkey, band, i, f, d); got != nil && got.Error() != want {
		t.Errorf("Load() = %q, want %q", got.Error(), want)
	}else if got == nil{
                t.Errorf("Load() = %q, want %q", error(nil), want)
	}
}

func Test_Loading_ssh_keys(t *testing.T) {
	pkey := os.Getenv("HOME")+"/.ssh/id_rsa"
	bkey := os.Getenv("HOME")+"/.ssh/id_rsa.pub"
	band := os.Getenv("HOME")+"/.ssh/band_memory"
        i := true
        f := false
        d := false
        if got := Startup(pkey, bkey, band, i, f, d); got != nil {
                t.Errorf("Load() = %q, expected error(nil)", got.Error())
        }
		
	
}

