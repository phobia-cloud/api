// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package login_test

import (
	"fmt"

	"phobia.cloud/api/login"
)

func ExampleVerify() {
	err := login.Verify(
		"cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
		"2015-03-23 17:39:22",
		"023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
		"20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
		2,
	)
	fmt.Println(err)
	// Output: <nil>
}
