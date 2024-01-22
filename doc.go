// Copyright 2024 Croonix. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
This module seeks to have a similarity to that found in [Verify the Google ID token on your server side](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
for other languages. It validates if the generated JWT corresponds
to Google and also provides the possibility to validate if the user
who issued the token is or is not from a specific domain.
*/
package gTokenVerifier
