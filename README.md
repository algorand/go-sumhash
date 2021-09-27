
Sumhash
====================


A Go implementation of Algorand's subset-sum hash function.
The library exports the subset sum hash function via a `hash.Hash` interface.


# Install

```bash
go get https://github.com/algorand/sumhash
```
Alternatively the same can be achieved if you use import in a package:

```bash
import "github.com/algorand/sumhash"
```
and run go get without parameters.

# Usage 


Construct a sumhash instacne with block size of 512.

```go
package main

import (
	"fmt"

	sumhash "github.com/algorand/sumhash"
)

func main() {
	h := sumhash.NewSumhash512(nil)
	input := []byte("sumhash input")
	_, _ = h.Write(input)

	sum := h.Sum(nil)
	fmt.Printf("subset sum hash value: %X", sum)
}

```

# Testing

```go
go test ./...
```

# Spec

The specification of the function as well as the security parameters
can be found [here](https://github.com/algorand/snark-friendly-crypto/tree/master/spec)  
